// example-client.ts - Example of how to use the API
import axios from 'axios';

async function openDoor(doorId: number) {
  try {
    const response = await axios.post('http://localhost:3000/api/door/control', {
      doorId: doorId,
      command: 'open'
    });
    
    console.log('Door control response:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error opening door:', error);
    throw error;
  }
}

// Call the function with door ID 1
openDoor(1)
  .then(() => console.log('Door open command sent successfully'))
  .catch(err => console.error('Failed to send door open command:', err));