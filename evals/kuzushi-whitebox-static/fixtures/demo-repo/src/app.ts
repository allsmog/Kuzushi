import express from "express";
import userRoutes from "./routes/users";
import orderRoutes from "./routes/orders";

const app = express();
app.use(userRoutes);
app.use(orderRoutes);

export default app;
