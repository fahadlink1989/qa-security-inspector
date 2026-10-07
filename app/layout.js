import './globals.css';

export const metadata = {
  title: 'Inspector — Security & UX QA',
  description: 'Authorized, non-destructive security and usability checks for web applications.'
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
