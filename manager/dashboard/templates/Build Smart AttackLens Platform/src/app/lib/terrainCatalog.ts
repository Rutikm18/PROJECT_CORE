import { useEffect, useState } from "react";

export interface TerrainMeta {
  id: string;
  label: string;
  validation_label: string;
  description: string;
  color: string;
  route: string;
  categories: string[];
}

export function parseTerrainCatalog(value: unknown): TerrainMeta[] {
  if (!value || typeof value !== "object") return [];
  const rows = (value as { terrains?: unknown }).terrains;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row) => {
    if (!row || typeof row !== "object") return [];
    const item = row as Record<string, unknown>;
    if (typeof item.id !== "string" || typeof item.label !== "string") return [];
    return [{
      id: item.id,
      label: item.label,
      validation_label: typeof item.validation_label === "string" ? item.validation_label : item.label,
      description: typeof item.description === "string" ? item.description : "",
      color: typeof item.color === "string" ? item.color : "#64748b",
      route: typeof item.route === "string" ? item.route : `/terrain/${item.id}`,
      categories: Array.isArray(item.categories)
        ? item.categories.filter((category): category is string => typeof category === "string")
        : [],
    }];
  });
}

export function useTerrainCatalog(): TerrainMeta[] {
  const [terrains, setTerrains] = useState<TerrainMeta[]>([]);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/v1/soc/terrains", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error(String(response.status))))
      .then((body) => setTerrains(parseTerrainCatalog(body)))
      .catch(() => { /* keep navigation usable while metadata is unavailable */ });
    return () => controller.abort();
  }, []);

  return terrains;
}
