package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errJobNotFound = errors.New("job not found")

type jobState struct {
	Status   string // pending|running|succeeded|failed|cancelled
	Stdout   string
	Stderr   string
	ExitCode *int
}

func (s *server) ensureJob(ctx context.Context, name string, req *launchRequest) error {
	jobs := s.k8s.BatchV1().Jobs(s.namespace)
	if _, err := jobs.Get(ctx, name, metav1.GetOptions{}); err == nil {
		return nil // idempotent — already exists
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get job %s: %w", name, err)
	}

	envVars := make([]corev1.EnvVar, 0, len(req.Env))
	for k, v := range req.Env {
		envVars = append(envVars, corev1.EnvVar{Name: k, Value: v})
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.namespace,
			Labels: map[string]string{
				"app":                       "kuzushi-sandbox-runner",
				"kuzushi.allsmog.dev/client": req.ClientID,
				"kuzushi.allsmog.dev/run":    req.RunID,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            int32Ptr(0),
			TTLSecondsAfterFinished: int32Ptr(86400),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "kuzushi-sandbox-runner"}},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name:    "runner",
						Image:   s.image,
						Command: req.Command[:1],
						Args:    req.Command[1:],
						Env:     envVars,
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("250m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("2000m"),
								corev1.ResourceMemory: resource.MustParse("4Gi"),
							},
						},
					}},
				},
			},
		},
	}
	if _, err := jobs.Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create job %s: %w", name, err)
	}
	return nil
}

func (s *server) fetchState(ctx context.Context, name string) (*jobState, error) {
	jobs := s.k8s.BatchV1().Jobs(s.namespace)
	job, err := jobs.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, errJobNotFound
		}
		return nil, fmt.Errorf("get job %s: %w", name, err)
	}

	status := "pending"
	switch {
	case job.Status.Succeeded > 0:
		status = "succeeded"
	case job.Status.Failed > 0:
		status = "failed"
	case job.Status.Active > 0:
		status = "running"
	}

	state := &jobState{Status: status}
	pod, err := s.findPod(ctx, name)
	if err == nil && pod != nil {
		state.Stdout, state.Stderr = s.fetchLogs(ctx, pod)
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			for _, cstatus := range pod.Status.ContainerStatuses {
				if cstatus.State.Terminated != nil {
					exit := int(cstatus.State.Terminated.ExitCode)
					state.ExitCode = &exit
					break
				}
			}
		}
	}
	return state, nil
}

func (s *server) findPod(ctx context.Context, jobName string) (*corev1.Pod, error) {
	pods, err := s.k8s.CoreV1().Pods(s.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, nil
	}
	// Return the most recently created pod.
	chosen := &pods.Items[0]
	for i := range pods.Items {
		if pods.Items[i].CreationTimestamp.After(chosen.CreationTimestamp.Time) {
			chosen = &pods.Items[i]
		}
	}
	return chosen, nil
}

func (s *server) fetchLogs(ctx context.Context, pod *corev1.Pod) (stdout string, stderr string) {
	// k8s merges stdout/stderr into a single log stream by default.
	// We surface it as `stdout` here; runner images that need a real
	// split should write stderr to a separate sidecar log.
	req := s.k8s.CoreV1().Pods(s.namespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", ""
	}
	defer func() { _ = stream.Close() }()
	body, err := io.ReadAll(stream)
	if err != nil {
		return "", ""
	}
	return string(body), ""
}

func jobName(clientID, runID string) string {
	// RFC 1123 sanitisation: lowercase alphanumeric + hyphen, ≤63 chars.
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'z':
				b.WriteRune(r)
			case r >= 'A' && r <= 'Z':
				b.WriteRune(r + 32)
			default:
				b.WriteRune('-')
			}
		}
		return b.String()
	}
	out := fmt.Sprintf("kuzushi-%s-%s", clean(clientID), clean(runID))
	if len(out) > 63 {
		out = out[:63]
	}
	return strings.TrimRight(out, "-")
}

func int32Ptr(v int32) *int32 { return &v }
