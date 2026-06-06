export type HealthResponse = {
  status: string;
  service: string;
};

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch("/api/health");

  if (!response.ok) {
    throw new Error(`health check failed: ${response.status}`);
  }

  return response.json() as Promise<HealthResponse>;
}
