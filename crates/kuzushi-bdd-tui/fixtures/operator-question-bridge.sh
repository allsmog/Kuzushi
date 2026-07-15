#!/bin/sh
request="$(cat)"

case "$request" in
  *'"type":"next-step-preflight"'*)
    printf '%s' '{"ok":true}'
    ;;
  *'"type":"tool_result"'*)
    printf '%s' '{"ok":true,"step":"final","text":"Operator chose repository scope; deterministic answer complete.","costUsd":0.02}'
    ;;
  *'"type":"next-step"'*)
    printf '%s' '{"ok":true,"step":"tool_call","call":{"name":"request_user_input","input":{"questions":[{"id":"scope","header":"Scope","prompt":"Choose the scan scope.","options":[{"label":"Changed files","description":"Limit the scan to the current diff.","recommended":true},{"label":"Repository","description":"Scan the complete target repository.","recommended":false}]}]},"callId":"bdd-question-1"},"costUsd":0.01}'
    ;;
  *)
    printf '%s' '{"ok":false,"error":"unexpected bridge envelope"}'
    ;;
esac
