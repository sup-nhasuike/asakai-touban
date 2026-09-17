// Cloudflare Pages Functions のミドルウェア。
// 静的ファイル（public/配下）が配信される前に、すべてのリクエストへBasic認証をかける。
// 認証情報はCloudflareの環境変数（Pagesプロジェクトの Settings > Environment variables）
// から読み込み、コードには直書きしない。
export async function onRequest(context) {
	const { request, env, next } = context;

	const unauthorized = () =>
		new Response("Authentication required.", {
			status: 401,
			headers: { "WWW-Authenticate": 'Basic realm="Restricted", charset="UTF-8"' },
		});

	// Cloudflareの管理画面への貼り付け時に紛れ込んだ余分な空白・改行の影響を受けないようにする
	const expectedUser = (env.BASIC_AUTH_USER || "").trim();
	const expectedPassword = (env.BASIC_AUTH_PASSWORD || "").trim();

	// 環境変数が未設定の場合は、誤って無認証で公開されることがないよう常に拒否する
	if (!expectedUser || !expectedPassword) {
		return unauthorized();
	}

	const authHeader = request.headers.get("Authorization") || "";
	if (!authHeader.startsWith("Basic ")) {
		return unauthorized();
	}

	let decoded;
	try {
		decoded = atob(authHeader.slice("Basic ".length));
	} catch (e) {
		return unauthorized();
	}

	const separatorIndex = decoded.indexOf(":");
	if (separatorIndex === -1) {
		return unauthorized();
	}
	const user = decoded.slice(0, separatorIndex).trim();
	const password = decoded.slice(separatorIndex + 1).trim();

	// iOSのSafari等、認証ポップアップのユーザー名欄が自動で先頭を大文字にする場合があるため、
	// ユーザー名は大文字小文字を区別しない（パスワードは区別したままにする）
	const userMatches = constantTimeEqual(user.toLowerCase(), expectedUser.toLowerCase());
	const passwordMatches = constantTimeEqual(password, expectedPassword);
	if (!userMatches || !passwordMatches) {
		return unauthorized();
	}

	return next();
}

// タイミング攻撃を避けるため、文字列比較は長さを揃えたうえで全バイトを走査する
function constantTimeEqual(a, b) {
	const encoder = new TextEncoder();
	const bufA = encoder.encode(a);
	const bufB = encoder.encode(b);
	const maxLength = Math.max(bufA.length, bufB.length);
	let diff = bufA.length === bufB.length ? 0 : 1;
	for (let i = 0; i < maxLength; i++) {
		diff |= (bufA[i] || 0) ^ (bufB[i] || 0);
	}
	return diff === 0;
}
