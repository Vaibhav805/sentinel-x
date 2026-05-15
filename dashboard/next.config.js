// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  // Allow browser to connect to socket server on :3001
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [{ key: "X-Frame-Options", value: "SAMEORIGIN" }],
      },
    ];
  },
};

module.exports = nextConfig;

// ─── tailwind.config.js ───────────────────────────────────────────────────────
// /** @type {import('tailwindcss').Config} */
// module.exports = {
//   content: ["./src/**/*.{js,jsx,ts,tsx}"],
//   theme: { extend: {} },
//   plugins: [],
// };