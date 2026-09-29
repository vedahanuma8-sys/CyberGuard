import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#020617", // slate-950
        surface: "#0f172a",    // slate-900
        card: "#0f172a",       // slate-900
        border: "#1e293b",     // slate-800
        accent: {
          safe: "#10b981",       // emerald-500
          cyber: "#06b6d4",      // cyan-500
          warning: "#f59e0b",    // amber-500
          danger: "#ef4444",     // red-500
        },
      },
    },
  },
  plugins: [],
};

export default config;
