const { spawn } = require('child_process')

const pythonProcess = spawn('python3', ['main.py'], { stdio: 'inherit' })

pythonProcess.on('exit', (code) => {
	console.log(`Python script exited with code ${code}`)
})
