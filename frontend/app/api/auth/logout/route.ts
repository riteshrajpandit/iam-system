import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST(request: Request) {
    const cookieStore = await cookies();
    const refreshToken = cookieStore.get('refresh_token')?.value;
    
    const IAM_URL = process.env.NEXT_PUBLIC_IAM_URL;
    const CLIENT_ID = process.env.NEXT_PUBLIC_CLIENT_ID;

    // Attempt to revoke on backend
    if (refreshToken && IAM_URL && CLIENT_ID) {
        try {
            const body = new URLSearchParams({
                token: refreshToken,
                token_type_hint: 'refresh_token',
                client_id: CLIENT_ID
            });

            await fetch(`${IAM_URL}/o/revoke/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: body.toString()
            });
        } catch (error) {
            console.error("Revocation failed", error);
            // We continue to clear cookies anyway
        }
    }

    const response = NextResponse.json({ success: true });
    
    // Clear cookies
    response.cookies.delete('access_token');
    response.cookies.delete('refresh_token');
    
    return response;
}
