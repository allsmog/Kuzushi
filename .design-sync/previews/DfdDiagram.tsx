import { TermFrame, DfdDiagram } from "@kuzushi/tui-kit";

// Internet → App VPC → Data, two trust-boundary crossings (HTTPS, SQL).
export function CheckoutFlow() {
  return (
    <TermFrame chromeless cols={72}>
      <DfdDiagram
        zones={[
          {
            name: "Internet",
            nodes: [{ label: "Browser", kind: "entity" }],
            flowToNext: { label: "HTTPS", boundary: true },
          },
          {
            name: "App VPC",
            nodes: [
              { label: "API Gateway", kind: "process" },
              { label: "Order Service", kind: "process" },
            ],
            flowToNext: { label: "SQL", boundary: true },
          },
          {
            name: "Data",
            nodes: [{ label: "Postgres", kind: "store" }],
          },
        ]}
      />
    </TermFrame>
  );
}

// A deeper flow with a third-party entity and an internal (in-zone) hop.
export function PaymentFlow() {
  return (
    <TermFrame chromeless cols={76}>
      <DfdDiagram
        zones={[
          {
            name: "Internet",
            nodes: [{ label: "Mobile Client", kind: "entity" }],
            flowToNext: { label: "HTTPS / OAuth", boundary: true },
          },
          {
            name: "App VPC",
            nodes: [
              { label: "Payment API", kind: "process" },
              { label: "Fraud Check", kind: "process" },
            ],
            flowToNext: { label: "TLS webhook", boundary: true },
          },
          {
            name: "Third Party",
            nodes: [{ label: "Stripe", kind: "entity" }],
            flowToNext: { label: "queue write", boundary: false },
          },
          {
            name: "Data",
            nodes: [{ label: "Ledger DB", kind: "store" }],
          },
        ]}
      />
    </TermFrame>
  );
}
