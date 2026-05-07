package main

// (intentionally empty — auth lives in main.go::server.authOk so the
// handler bodies can short-circuit early. This file is reserved for
// per-tenant auth helpers when the adapter graduates beyond a single
// global API key.)
