'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

interface UserProfile {
  sub: string;
  email?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const res = await fetch('/api/user'); // Call our own proxy

        if (res.status === 401 || res.status === 403) {
           router.push('/');
           return;
        }

        if (!res.ok) {
          throw new Error('Failed to fetch user info');
        }

        const data = await res.json();
        setUser(data);
      } catch (err: any) {
        console.error(err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchUserInfo();
  }, [router]);

  const handleLogout = async () => {
      await fetch('/api/auth/logout', { method: 'POST' });
      // Redirect to Identity Provider to clear global session
      const IAM_URL = process.env.NEXT_PUBLIC_IAM_URL;
      window.location.href = `${IAM_URL}/o/logout/?post_logout_redirect_uri=${window.location.origin}`;
  };

  if (loading) {
     return (
        <div className="flex min-h-screen items-center justify-center bg-gray-50">
             <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
        </div>
     );
  }

  if (error) {
      return (
          <div className="flex min-h-screen items-center justify-center bg-gray-50">
              <div className="text-red-500">Error loading profile: {error}</div>
          </div>
      );
  }

  return (
    <main className="min-h-screen bg-gray-100 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
            <button 
                onClick={handleLogout}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
            >
                Logout
            </button>
        </div>

        <div className="bg-white shadow rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-xl font-semibold text-gray-800">User Profile</h2>
            </div>
            
            <div className="p-6">
                <div className="flex items-center space-x-6 mb-6">
                    <div className="h-20 w-20 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 text-2xl font-bold">
                        {user?.given_name?.[0] || user?.email?.[0] || '?'}
                    </div>
                    <div>
                        <h3 className="text-2xl font-bold text-gray-900">{user?.name}</h3>
                        <p className="text-gray-500">{user?.email}</p>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-gray-50 p-4 rounded-md">
                        <span className="block text-sm font-medium text-gray-500 mb-1">User ID (Subject)</span>
                        <code className="block text-sm bg-gray-200 p-2 rounded text-gray-800 break-all">{user?.sub}</code>
                    </div>
                    
                    <div className="bg-gray-50 p-4 rounded-md">
                        <span className="block text-sm font-medium text-gray-500 mb-1">Preferred Username</span>
                        <span className="block text-gray-900">{user?.preferred_username}</span>
                    </div>

                    <div className="bg-gray-50 p-4 rounded-md">
                        <span className="block text-sm font-medium text-gray-500 mb-1">First Name</span>
                        <span className="block text-gray-900">{user?.given_name}</span>
                    </div>

                    <div className="bg-gray-50 p-4 rounded-md">
                        <span className="block text-sm font-medium text-gray-500 mb-1">Last Name</span>
                        <span className="block text-gray-900">{user?.family_name}</span>
                    </div>
                </div>
                
                <div className="mt-8 pt-6 border-t border-gray-200">
                     <p className="text-sm text-gray-500">
                        This data was retrieved securely from the IDP UserInfo endpoint using an OAuth 2.0 Access Token.
                     </p>
                </div>
            </div>
        </div>
      </div>
    </main>
  );
}
