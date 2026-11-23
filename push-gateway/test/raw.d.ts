// Vite `?raw` imports: the file as text (the tests read wrangler.toml this way).
declare module "*?raw" {
  const text: string;
  export default text;
}
