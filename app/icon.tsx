import { ImageResponse } from "next/og";

export const size = {
  width: 512,
  height: 512,
};

export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          alignItems: "center",
          background: "#111827",
          display: "flex",
          justifyContent: "center",
        }}
      >
        <svg width="260" height="260" viewBox="0 0 24 24" fill="none">
          <path
            d="M7 10V8C7 5.24 9.24 3 12 3C14.76 3 17 5.24 17 8V10"
            stroke="#ffffff"
            strokeLinecap="round"
            strokeWidth="2"
          />
          <path
            d="M6.5 10H17.5C18.6 10 19.5 10.9 19.5 12V19C19.5 20.1 18.6 21 17.5 21H6.5C5.4 21 4.5 20.1 4.5 19V12C4.5 10.9 5.4 10 6.5 10Z"
            stroke="#ffffff"
            strokeWidth="2"
          />
        </svg>
      </div>
    ),
    size,
  );
}
