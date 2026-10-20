// The built-in roles the demo can be viewed as (plain data, no demo code).
export const personas = ["viewer", "analyst", "operator", "scoped_operator", "team_lead", "admin"] as const;
export type Persona = (typeof personas)[number];
