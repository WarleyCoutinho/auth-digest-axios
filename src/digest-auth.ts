import axios, { AxiosInstance, AxiosHeaders } from "axios";
import crypto from "crypto";

interface DigestAuthConfig {
  username: string;
  password: string;
}

interface DigestChallenge {
  realm: string;
  nonce: string;
  qop?: string;
  opaque?: string;
  algorithm?: string;
}

function parseDigestChallenge(authHeader: string): DigestChallenge {
  const challenge: DigestChallenge = { realm: "", nonce: "" };
  // Expressão regular melhorada para lidar corretamente com aspas e valores
  const regex = /(\w+)=(?:"([^"]*)"|([^,]*))/g;
  let match;

  while ((match = regex.exec(authHeader)) !== null) {
    const key = match[1].toLowerCase();
    // Use o valor com aspas se estiver presente, caso contrário use o valor sem aspas
    const value = match[2] !== undefined ? match[2] : match[3];
    
    switch (key) {
      case "realm":
        challenge.realm = value;
        break;
      case "nonce":
        challenge.nonce = value;
        break;
      case "qop":
        challenge.qop = value;
        break;
      case "opaque":
        challenge.opaque = value;
        break;
      case "algorithm":
        challenge.algorithm = value;
        break;
    }
  }

  return challenge;
}

// Função auxiliar para formatar o contador de nonce
function formatNonceCount(nc: number): string {
  return nc.toString(16).padStart(8, "0");
}

function calculateDigestResponse(
  username: string,
  password: string,
  challenge: DigestChallenge,
  nc: number,
  cnonce: string,
  method: string,
  uri: string
): string {
  const algorithm = challenge.algorithm || "MD5";
  const hashFunction = (data: string) => crypto.createHash(algorithm.toLowerCase()).update(data).digest("hex");
  
  const ha1 = hashFunction(`${username}:${challenge.realm}:${password}`);
  const ha2 = hashFunction(`${method}:${uri}`);

  const ncFormatted = formatNonceCount(nc);
  
  let responseBase: string;
  if (challenge.qop) {
    responseBase = `${ha1}:${challenge.nonce}:${ncFormatted}:${cnonce}:${challenge.qop}:${ha2}`;
  } else {
    responseBase = `${ha1}:${challenge.nonce}:${ha2}`;
  }

  return hashFunction(responseBase);
}

export async function createDigestAuth(
  config: DigestAuthConfig
): Promise<AxiosInstance> {
  const { username, password } = config;
  const axiosInstance = axios.create();
  let nc = 0; // Nonce count
  let cachedChallenge: DigestChallenge | null = null;

  axiosInstance.interceptors.request.use(async (requestConfig) => {
    try {
      // Obter o desafio Digest na primeira requisição ou se o contador for alto
      if (!cachedChallenge || nc > 9999) {
        console.log("Requesting new digest challenge...");
        
        const initialResponse = await axios.request({
          method: requestConfig.method,
          url: requestConfig.url,
          baseURL: requestConfig.baseURL,
          maxRedirects: 0,
          validateStatus: (status) => status === 401,
          timeout: 5000, // Adicionar timeout para evitar espera infinita
        });

        if (initialResponse.status !== 401) {
          throw new Error(
            `Expected 401 status code but got ${initialResponse.status}`
          );
        }

        // Obter e verificar o cabeçalho WWW-Authenticate
        const authHeader = initialResponse.headers["www-authenticate"];
        if (!authHeader) {
          throw new Error("Missing WWW-Authenticate header");
        }
        
        if (!authHeader.toLowerCase().includes("digest ")) {
          throw new Error(`Invalid authentication type: ${authHeader}`);
        }

        // Analisar o desafio Digest
        cachedChallenge = parseDigestChallenge(authHeader);
        console.log("Desafio analisado:", cachedChallenge);
        
        // Validar os campos obrigatórios
        if (!cachedChallenge.realm || !cachedChallenge.nonce) {
          throw new Error(`Invalid digest challenge: ${JSON.stringify(cachedChallenge)}`);
        }
        
        nc = 1; // Reiniciar o contador de nonce
      } else {
        nc++; // Incrementar contador para solicitações subsequentes
      }

      // Gerar um cliente nonce aleatório
      const cnonce = crypto.randomBytes(8).toString("hex");
      
      // Obter o URI a partir da URL
      const urlString = requestConfig.url || "";
      let uri = urlString;
      
      try {
        // Tentar extrair apenas o caminho + consulta da URL
        const urlObj = new URL(urlString, requestConfig.baseURL);
        uri = urlObj.pathname + urlObj.search;
      } catch (e) {
        // Falha ao analisar a URL, manter o URI original
        console.warn("Failed to parse URL, using original:", urlString);
      }
      
      // Validar o desafio Digest
      if (!cachedChallenge) {
        throw new Error("No valid digest challenge available");
      }

      // Formatar o contador de nonce corretamente
      const ncValue = formatNonceCount(nc);

      // Calcular a resposta Digest
      const digestResponse = calculateDigestResponse(
        username,
        password,
        cachedChallenge,
        nc,
        cnonce,
        requestConfig.method?.toUpperCase() || "GET",
        uri
      );

      // Montar o cabeçalho de autorização Digest
      let authValue = `Digest username="${username}", realm="${cachedChallenge.realm}", nonce="${cachedChallenge.nonce}", uri="${uri}", response="${digestResponse}"`;

      if (cachedChallenge.qop) {
        authValue += `, qop=${cachedChallenge.qop}, nc=${ncValue}, cnonce="${cnonce}"`;
      }

      if (cachedChallenge.opaque) {
        authValue += `, opaque="${cachedChallenge.opaque}"`;
      }

      if (cachedChallenge.algorithm) {
        authValue += `, algorithm=${cachedChallenge.algorithm}`;
      }

      // Certificar-se de que temos um objeto de cabeçalhos válido
      if (!requestConfig.headers) {
        requestConfig.headers = new AxiosHeaders();
      }
      
      // Atualizar o cabeçalho de autorização
      requestConfig.headers.set('Authorization', authValue);

      console.log("Using auth header:", authValue);
      return requestConfig;
    } catch (error) {
      console.error("Digest auth error:", error);
      throw error;
    }
  });

  // Adicionar um interceptor de resposta para lidar com falhas de autenticação
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error) => {
      if (error.response && error.response.status === 401 && cachedChallenge) {
        // Limpar o desafio em cache para forçar uma nova tentativa de autenticação
        console.log("Auth failed with 401, clearing cached challenge");
        cachedChallenge = null;
        nc = 0;
        
        // Se quiser implementar uma nova tentativa automática:
        // return axiosInstance(error.config);
      }
      return Promise.reject(error);
    }
  );

  return axiosInstance;
}