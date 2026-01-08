import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const { code, codeVerifier } = await request.json();

    const IAM_URL = process.env.NEXT_PUBLIC_IAM_URL;
    const CLIENT_ID = process.env.NEXT_PUBLIC_CLIENT_ID;
    const REDIRECT_URI = process.env.NEXT_PUBLIC_REDIRECT_URI;

    if (!IAM_URL || !CLIENT_ID || !REDIRECT_URI) {
      return NextResponse.json({ error: 'Server configuration error' }, { status: 500 });
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code: code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    });

    const res = await fetch(`${IAM_URL}/o/token/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    const data = await res.json();

    if (!res.ok) {
        return NextResponse.json({ error: data.error_description || 'Token exchange failed' }, { status: res.status });
    }

    // Create the response
    const response = NextResponse.json({ success: true });

    // Set secure cookies
    // Access Token
    response.cookies.set('access_token', data.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: data.expires_in // usually 36000 seconds
    });

    // Refresh Token
    if (data.refresh_token) {
        response.cookies.set('refresh_token', data.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            maxAge: 30 * 24 * 60 * 60 // 30 days
        });
    }

    // ID Token (optional, depends if you need it accessible or hidden)
    // Often ID token is safe to read in JS, but for strict session management keeping it hidden is fine if backend proxy parses it.
    // For simplicity, we'll keep it hidden too or not set it if not used by proxy.
    
    return response;

  } catch (error: any) {
    console.error("Exchange Error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
