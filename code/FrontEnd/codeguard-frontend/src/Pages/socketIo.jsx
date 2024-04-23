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
      setScanningLogs((prevLogs) => [...prevLogs, data]);
    });

    return () => {
      socket.disconnect();
    };
  }, [setScanningLogs]);

  return null;
};

export default SocketIO;