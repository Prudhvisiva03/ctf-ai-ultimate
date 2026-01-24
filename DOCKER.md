# Docker Usage for CTF-AI Ultimate 🐳

## Quick Start with Docker

### Build the Docker image:
```bash
docker build -t ctf-ai-ultimate .
```

### Run interactively:
```bash
docker run -it --rm \
  -v $(pwd)/challenges:/challenges \
  -v $(pwd)/output:/app/output \
  -e OPENAI_API_KEY="your-key-here" \
  ctf-ai-ultimate
```

### Or use Docker Compose:
```bash
# Create .env file with your API keys
echo "OPENAI_API_KEY=your-key" > .env

# Start container
docker-compose up -d

# Attach to container
docker-compose exec ctf-ai bash

# Inside container
ctf-ai
> solve /challenges/challenge.png
```

## Volume Mounts

- `/challenges` - Place your CTF files here
- `/app/output` - Analysis results saved here
- `/app/config.json` - Mount your custom config

## Environment Variables

- `OPENAI_API_KEY` - Your OpenAI API key
- `CLAUDE_API_KEY` - Your Claude API key
- `GROQ_API_KEY` - Your Groq API key

## Example Commands

### Analyze a challenge file:
```bash
docker run -it --rm -v $(pwd):/challenges ctf-ai-ultimate \
  python3 ctf-ai.py --solve /challenges/stego.png
```

### Use with Ollama (local AI):
```bash
# Run Ollama separately
docker run -d -p 11434:11434 --name ollama ollama/ollama
docker exec ollama ollama pull llama3

# Link CTF-AI container
docker run -it --rm \
  --link ollama:ollama \
  -e OLLAMA_HOST=http://ollama:11434 \
  ctf-ai-ultimate
```

## Benefits of Docker

✅ Isolated environment  
✅ All tools pre-installed  
✅ Consistent across systems  
✅ Easy deployment  
✅ No system pollution  

Happy Dockerized CTF Hunting! 🚀
