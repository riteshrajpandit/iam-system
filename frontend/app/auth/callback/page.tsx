'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function CallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState('Processing login...');
  const [error, setError] = useState<string | null>(null);
  const dataFetchedRef = useRef(false);

  useEffect(() => {
    // Prevent double-execution in React Strict Mode
    if (dataFetchedRef.current) return;
    dataFetchedRef.current = true;

    const fetchToken = async () => {
      const code = searchParams.get('code');
      const state = searchParams.get('state'); // In a real app, verify this matches sessionStorage

      if (!code) {
        setError("Authorization code is missing.");
        setStatus('Error');
        return;
      }

      const verifier = sessionStorage.getItem('pkce_code_verifier');
      if (!verifier) {
        setError("Missing PKCE code verifier. Did you start the login flow from this app?");
        setStatus('Error');
        return;
      }

      setStatus('Exchanging code for token...');

      try {
        // Exchange code using Next.js API Route (Server Side) which sets HttpOnly cookies
        const res = await fetch('/api/auth/exchange', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ code, codeVerifier: verifier })
        });

        const data = await res.json();

        if (!res.ok) {
            console.error("Token exchange failed", data);
            throw new Error(data.error || 'Token exchange failed');
        }

        // Success!
        setStatus('Login successful! Redirecting...');
        
        // Clear PKCE from session
        sessionStorage.removeItem('pkce_code_verifier');
        sessionStorage.removeItem('auth_state');

        // Redirect to dashboard
        router.push('/dashboard');

      } catch (err: any) {
          console.error(err);
          setError(err.message || "An unexpected error occurred.");
          setStatus("Error");
      }
    };

    fetchToken();
  }, [searchParams, router]);

  if (error) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-red-50 text-red-900 p-4">
        <div className="max-w-md w-full bg-white p-8 rounded-lg shadow-xl border border-red-200">
            <h1 className="text-2xl font-bold mb-4 flex items-center">
                <svg className="w-8 h-8 mr-2 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Login Failed
            </h1>
            <p className="mb-6 text-red-700 bg-red-50 p-3 rounded">
                {error}
            </p>
            <a href="/" className="block w-full text-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                Return Home
            </a>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-zinc-950 text-white">
      <div className="flex flex-col items-center space-y-4">
         <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
         <h2 className="text-xl font-mono">{status}</h2>
      </div>
    </div>
  );
}
