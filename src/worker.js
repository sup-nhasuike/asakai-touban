// 静的ファイル（index.html等）の手前でBasic認証をかけるWorker。
// 認証情報は環境変数（Cloudflareのシークレット）から読み込み、コードには直書きしない。
export default {
	async fetch(request, env) {
		const unauthorized = () =>
			new Response("Authentication required.", {
				status: 401,
				headers: { "WWW-Authenticate": 'Basic realm="Restricted", charset="UTF-8"' },
			});

		const expectedUser = env.BASIC_AUTH_USER;
		const expectedPassword = env.BASIC_AUTH_PASSWORD;

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
		const user = decoded.slice(0, separatorIndex);
		const password = decoded.slice(separatorIndex + 1);

		if (!constantTimeEqual(user, expectedUser) || !constantTimeEqual(password, expectedPassword)) {
			return unauthorized();
		}

		return env.ASSETS.fetch(request);
	},
};

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
