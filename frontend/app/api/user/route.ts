import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function GET(request: Request) {
    const cookieStore = await cookies();
    let accessToken = cookieStore.get('access_token')?.value;
    const refreshToken = cookieStore.get('refresh_token')?.value;
    
    const IAM_URL = process.env.NEXT_PUBLIC_IAM_URL;
    const CLIENT_ID = process.env.NEXT_PUBLIC_CLIENT_ID;

    if (!IAM_URL || !CLIENT_ID) {
        return NextResponse.json({ error: "Configuration Error" }, { status: 500 });
    }

    if (!accessToken && !refreshToken) {
        return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    // Helper to fetch user info
    const fetchUser = async (token: string) => {
        return fetch(`${IAM_URL}/o/userinfo/`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
    };

    // 1. Try with existing access token
    if (accessToken) {
        const res = await fetchUser(accessToken);
        if (res.ok) {
            return NextResponse.json(await res.json());
        }
        // If not 401, return the error
        if (res.status !== 401) {
             return NextResponse.json({ error: "Failed to fetch user info" }, { status: res.status });
        }
    }

    // 2. If we are here, either no access token OR it expired (401). Try Refresh.
    if (!refreshToken) {
        return NextResponse.json({ error: "Session expired" }, { status: 401 });
    }

    try {
        const body = new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: CLIENT_ID,
            refresh_token: refreshToken,
        });

        const refreshRes = await fetch(`${IAM_URL}/o/token/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString()
        });

        if (!refreshRes.ok) {
            // Refresh failed - session is dead
            return NextResponse.json({ error: "Session expired" }, { status: 401 });
        }

        const tokens = await refreshRes.json();
        const newAccessToken = tokens.access_token;
        const newRefreshToken = tokens.refresh_token; // Sometimes returned, sometimes not (rotation)

        // 3. Retry UserInfo with new token
        const userRes = await fetchUser(newAccessToken);
        
        if (!userRes.ok) {
             return NextResponse.json({ error: "Failed to fetch user info after refresh" }, { status: userRes.status });
        }

        const userData = await userRes.json();

        // 4. Create Response and Set New Cookies
        const response = NextResponse.json(userData);

        response.cookies.set('access_token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            maxAge: tokens.expires_in
        });

        if (newRefreshToken) {
             response.cookies.set('refresh_token', newRefreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                path: '/',
                maxAge: 30 * 24 * 60 * 60 
            });
        }

        return response;

    } catch (error) {
        console.error("Refresh Error", error);
        return NextResponse.json({ error: "Internal Error" }, { status: 500 });
    }
}
