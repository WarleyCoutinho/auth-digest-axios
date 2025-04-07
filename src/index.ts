import Fastify from 'fastify';
import { z } from 'zod';
import dotenv from 'dotenv';
import { createDigestAuth } from './digest-auth';





// Load environment variables
dotenv.config();

// Define schemas using Zod
const DoorCommandSchema = z.object({
  doorId: z.number().int().positive(),
  command: z.enum(['open', 'close', 'temporaryOpen', 'temporaryClose'])
});

type DoorCommand = z.infer<typeof DoorCommandSchema>;

// Create Fastify instance
const fastify = Fastify({
  logger: true
});

// Define the door control API client
class DoorControlClient {
  private baseUrl: string;
  private username: string;
  private password: string;

  constructor() {
    if (!process.env.DOOR_API_BASE_URL || !process.env.DOOR_API_USERNAME || !process.env.DOOR_API_PASSWORD) {
      throw new Error('Missing required environment variables');
    }

    this.baseUrl = process.env.DOOR_API_BASE_URL!;
    this.username = process.env.DOOR_API_USERNAME!;
    this.password = process.env.DOOR_API_PASSWORD!;
  
  }

  async controlDoor(doorId: number, command: string): Promise<any> {
    const url = `${this.baseUrl}/AccessControl/RemoteControl/door/${doorId}`;
    const xmlData = `<RemoteControlDoor><cmd>${command}</cmd></RemoteControlDoor>`;

    try {
      // Use o adaptador de autenticação Digest
      const axiosWithDigestAuth = await createDigestAuth({
        username: this.username,
        password: this.password
      });

      const response = await axiosWithDigestAuth({
        method: 'PUT',
        url: url,
        data: xmlData,
        headers: {
          'Content-Type': 'application/xml'
        }
      });

      return response.data;
    } catch (error) {
      console.error('Error controlling door:', error);
      throw error;
    }
  }
}

const doorClient = new DoorControlClient();

// Register routes
fastify.post('/api/door/control', async (request, reply) => {
  try {
    const payload = DoorCommandSchema.parse(request.body);
    const result = await doorClient.controlDoor(payload.doorId, payload.command);
    return { success: true, result };
  } catch (error) {
    if (error instanceof z.ZodError) {
      reply.code(400);
      return { success: false, error: error.errors };
    }
    
    reply.code(500);
    return { success: false, error: 'Failed to control door' };
  }
});

// Health check endpoint
fastify.get('/health', async () => {
  return { status: 'ok' };
});

// Start the server
const start = async () => {
  try {
    await fastify.listen({ port: 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();