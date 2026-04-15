/// <reference types="vite/client" />

// Allow importing CSS files with ?inline query as a string
declare module '*.css?inline' {
  const content: string;
  export default content;
}
