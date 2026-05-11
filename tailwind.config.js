/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/js/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        bg:      "#07070e",
        bg2:     "#0c0c1c",
        bg3:     "#10101f",
        accent:  "#4f9eff",
        accent2: "#818cf8",
        success: "#34d399",
        warn:    "#fbbf24",
        danger:  "#f87171",
        ink:     "#e6e6f0",
        muted:   "#64648c",
        faint:   "#38385a",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Fira Code"', "monospace"],
      },
      backdropBlur: { glass: "24px" },
      boxShadow: {
        glass: "0 1px 3px rgba(0,0,0,.5), 0 4px 20px rgba(0,0,0,.3)",
        "glass-lg": "0 8px 40px rgba(0,0,0,.5)",
      },
    },
  },
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/typography"),
  ],
};
