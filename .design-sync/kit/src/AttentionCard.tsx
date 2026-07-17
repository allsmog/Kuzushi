import * as React from "react";
import { KeyHints, cx } from "./shared.js";
import type { AttentionCardProps, AttentionKind } from "./types.js";

const ATTENTION_LABEL: Record<AttentionKind, string> = {
  question: "WAITING INPUT",
  confirmation: "CONFIRMATION REQUIRED",
  credential: "CREDENTIALS REQUIRED",
  approval: "APPROVAL REQUIRED",
};

export function AttentionCard({
  kind,
  title,
  body,
  detail,
  choices,
  selected = 0,
  controls,
}: AttentionCardProps): React.ReactElement {
  return (
    <section className={cx("kz-attention-card", `kz-attention-${kind}`)}>
      <div className="kz-attention-label">▸ {ATTENTION_LABEL[kind]}</div>
      <div className="kz-attention-title">{title}</div>
      <div className="kz-attention-body">{body}</div>
      {detail && <div className="kz-attention-detail">{detail}</div>}
      {choices?.length ? (
        <div className="kz-attention-choices">
          {choices.map((choice, index) => (
            <div className={cx("kz-attention-choice", index === selected && "kz-selected")} key={`${choice.key}:${choice.label}`}>
              <b>{choice.key}</b> {choice.label}{choice.detail && <span> · {choice.detail}</span>}
            </div>
          ))}
        </div>
      ) : null}
      <KeyHints hints={controls} />
    </section>
  );
}
