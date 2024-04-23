import React, { useEffect } from 'react';
import io from 'socket.io-client';

const SocketIO = ({ setScanningLogs }) => {
  useEffect(() => {
    const socket = io('http://localhost:5000');

    socket.on('connect', () => {
      console.log('Connected to server');
    });

    socket.on('disconnect', () => {
      console.log('Disconnected from server');
    });

    socket.on('output', (data) => {
      console.log('Received output:', data);
      // Split the data by newline and update the state with each line separately
      data.split('\n').forEach((log) => {
        if (log.trim() !== '') {
          setScanningLogs((prevLogs) => [...prevLogs, log]);
        }
      });
    });

    return () => {
      socket.disconnect();
    };
  }, [setScanningLogs]);

  return null;
};

export default SocketIO;