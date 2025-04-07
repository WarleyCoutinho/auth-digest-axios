import axios, { AxiosInstance, AxiosRequestConfig, AxiosHeaders } from "axios";
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
  const regex = /(\w+)=(?:"([^"]*)"|([^,]*))/g;
  let match;

  while ((match = regex.exec(authHeader)) !== null) {
    const key = match[1].toLowerCase();
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
  // Sempre use MD5 se não for especificado
  const algorithm = "MD5";
  const hashFunction = (data: string) => crypto.createHash(algorithm.toLowerCase()).update(data).digest("hex");
  
  const ha1 = hashFunction(`${username}:${challenge.realm}:${password}`);
  const ha2 = hashFunction(`${method}:${uri}`);

  const ncFormatted = formatNonceCount(nc);
  
  // Log dos valores usados para depuração
  console.log("Digest calculation values:", {
    username,
    realm: challenge.realm,
    method,
    uri,
    nonce: challenge.nonce,
    nc: ncFormatted,
    cnonce,
    qop: challenge.qop || "none",
    ha1,
    ha2
  });
  
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
  let nc = 0;
  let cachedChallenge: DigestChallenge | null = null;
  let retryCount = 0;
  const MAX_RETRIES = 2;

  axiosInstance.interceptors.request.use(async (requestConfig) => {
    try {
      // Se não temos um desafio ou o contador está alto, solicite um novo
      if (!cachedChallenge || nc > 99) {
        console.log("Requesting new digest challenge...");
        
        const initialResponse = await axios.request({
          method: requestConfig.method,
          url: requestConfig.url,
          baseURL: requestConfig.baseURL,
          maxRedirects: 0,
          validateStatus: (status) => status === 401,
          timeout: 5000,
        });

        if (initialResponse.status !== 401) {
          throw new Error(
            `Expected 401 status code but got ${initialResponse.status}`
          );
        }

        const authHeader = initialResponse.headers["www-authenticate"];
        if (!authHeader) {
          throw new Error("Missing WWW-Authenticate header");
        }
        
        if (!authHeader.toLowerCase().includes("digest ")) {
          throw new Error(`Invalid authentication type: ${authHeader}`);
        }

        // Extrair apenas a parte após "Digest " do cabeçalho
        const digestPart = authHeader.substring(authHeader.toLowerCase().indexOf("digest ") + 7);
        cachedChallenge = parseDigestChallenge(digestPart);
        console.log("Desafio analisado:", cachedChallenge);
        
        if (!cachedChallenge.realm || !cachedChallenge.nonce) {
          throw new Error(`Invalid digest challenge: ${JSON.stringify(cachedChallenge)}`);
        }
        
        nc = 1;
      } else {
        nc++;
      }

      const cnonce = crypto.randomBytes(8).toString("hex");
      
      // Extrair o URI da URL de forma mais robusta
      let uri: string;
      if (requestConfig.url?.startsWith("http")) {
        try {
          const urlObj = new URL(requestConfig.url);
          uri = urlObj.pathname + urlObj.search;
        } catch (e) {
          uri = requestConfig.url.replace(/^https?:\/\/[^\/]+/i, '');
        }
      } else if (requestConfig.baseURL && requestConfig.url) {
        try {
          const fullUrl = new URL(requestConfig.url, requestConfig.baseURL);
          uri = fullUrl.pathname + fullUrl.search;
        } catch (e) {
          uri = requestConfig.url;
        }
      } else {
        uri = requestConfig.url || "";
      }
      
      if (!cachedChallenge) {
        throw new Error("No valid digest challenge available");
      }

      const ncValue = formatNonceCount(nc);
      const method = requestConfig.method?.toUpperCase() || "GET";
      
      const digestResponse = calculateDigestResponse(
        username,
        password,
        cachedChallenge,
        nc,
        cnonce,
        method,
        uri
      );

      let authValue = `Digest username="${username}", realm="${cachedChallenge.realm}", nonce="${cachedChallenge.nonce}", uri="${uri}", response="${digestResponse}"`;

      if (cachedChallenge.qop) {
        authValue += `, qop=${cachedChallenge.qop}, nc=${ncValue}, cnonce="${cnonce}"`;
      }

      if (cachedChallenge.opaque) {
        authValue += `, opaque="${cachedChallenge.opaque}"`;
      }

      if (!requestConfig.headers) {
        requestConfig.headers = new AxiosHeaders();
      }
      
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