'use client';

import { useState } from 'react';
import { getLoginUrl } from '@/lib/auth';

export default function Home() {
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    try {
      setLoading(true);
      const url = await getLoginUrl();
      window.location.href = url;
    } catch (error) {
      console.error("Login failed", error);
      setLoading(false);
      alert("Failed to initialize login flow. Check console.");
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24 bg-white text-black">
      <h1 className="text-4xl font-bold">IOXET IAM Demo</h1>
      <div className="mt-8 flex gap-4">
        <button onClick={handleLogin} className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">Login with IOXET</button>
        <a href="/register" className="px-4 py-2 border border-blue-500 text-blue-500 rounded hover:bg-blue-50">Sign Up</a>
      </div>
    </main>
  );
}
