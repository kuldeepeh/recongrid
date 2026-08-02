import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Black / red hacker palette
        ink: {
          950: "#050506",
          900: "#0a0a0c",
          800: "#101014",
          700: "#17171d",
          600: "#22222b",
        },
        blood: {
          500: "#ff2d2d",
          600: "#e11414",
          700: "#a30d0d",
          900: "#3b0606",
        },
        neon: "#ff3b3b",
      },
      fontFamily: {
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 20px rgba(255,45,45,0.25)",
        "glow-sm": "0 0 8px rgba(255,45,45,0.35)",
      },
      backgroundImage: {
        "blood-gradient":
          "radial-gradient(120% 120% at 0% 0%, #1a0405 0%, #0a0a0c 45%, #050506 100%)",
        "blood-line":
          "linear-gradient(90deg, transparent, #ff2d2d, transparent)",
      },
      keyframes: {
        pulseGlow: {
          "0%, 100%": { opacity: "0.6" },
          "50%": { opacity: "1" },
        },
      },
      animation: {
        "pulse-glow": "pulseGlow 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
