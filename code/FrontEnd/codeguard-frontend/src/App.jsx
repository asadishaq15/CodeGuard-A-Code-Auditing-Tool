import { useState } from 'react'
import './App.css'
import MainPage from './Pages/main'
import SocketIO from './Pages/socketIo'

function App() {
  const [scanningLogs, setScanningLogs] = useState([]);

  return (
    <>
      <SocketIO setScanningLogs={setScanningLogs} />
      <MainPage scanningLogs={scanningLogs} />
    </>
  );
}

export default App;
