export interface ShellRoute<Input, Environment, Result> {
  readonly id: string;
  readonly aliases?: readonly string[];
  readonly usage: string;
  matches(
    input: Input,
    environment: Environment,
    route: ShellRoute<Input, Environment, Result>,
  ): boolean;
  execute(input: Input, environment: Environment): Result;
}

export type ShellRouteDefinition<Input, Environment, Result> = Omit<
  ShellRoute<Input, Environment, Result>,
  "usage"
> & {
  readonly usage?: string;
};

export function defineShellRoutes<Input, Environment, Result>(
  routes: readonly ShellRouteDefinition<Input, Environment, Result>[],
): readonly ShellRoute<Input, Environment, Result>[] {
  return routes.map((route) => ({
    ...route,
    usage: route.usage ?? route.aliases?.[0] ?? route.id,
  }));
}

export function routeShellInput<Input, Environment, Result>(
  input: Input,
  environment: Environment,
  routes: readonly ShellRoute<Input, Environment, Result>[],
): Result | undefined {
  return routes
    .find((route) => route.matches(input, environment, route))
    ?.execute(input, environment);
}

export function commandMatches(command: string, aliases: readonly string[]): boolean {
  return aliases.includes(command.toLowerCase());
}
