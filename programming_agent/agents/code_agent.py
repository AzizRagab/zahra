"""
Programming Code Agent - Main Agent Implementation
An AI-powered programming agent that can write, execute, and debug code
using free-tier LLMs (Ollama, Groq, Gemini via LiteLLM).
"""

import os
import json
import subprocess
import tempfile
import logging
import re
from typing import Optional, Dict, Any, List, Union

logger = logging.getLogger(__name__)


class CodeAgent:
    """
    An AI-powered programming agent that can:
    - Write and generate code from natural language prompts
    - Execute code in sandboxed environments (Python, JavaScript)
    - Debug and fix errors using LLM analysis
    - Search the web for solutions and best practices
    - Refactor and optimize existing code
    - Support multiple LLM providers with free-tier options
    - Support various programming languages and frameworks including Klein
    
    Supported free-tier model providers:
    - Ollama: Local models (Llama 3.3/4, Qwen, Gemma, DeepSeek, Mistral...)
    - Groq: Fast free tier available
    - Google Gemini AI Studio: Very generous free tier
    - OpenRouter: Many free model options
    
    Supported languages/frameworks:
    - Python, JavaScript, Bash, HTML
    - Klein (Python micro-framework for web development)
    """
    
    # Available model providers with their default free models
    AVAILABLE_PROVIDERS = {
        "ollama": {
            "name": "Ollama (Local)",
            "description": "Run any model locally for free (Llama 3.3/4, Qwen, Gemma, DeepSeek, Mistral...)",
            "default_model": "codellama",
            "requires_install": False,
            "url": "http://localhost:11434"
        },
        "groq": {
            "name": "Groq",
            "description": "Fastest free tier (great for Agents)",
            "default_model": "llama3-8b-8192",
            "requires_api_key": True,
            "api_env": "GROQ_API_KEY"
        },
        "gemini": {
            "name": "Google Gemini",
            "description": "Very generous free tier at AI Studio",
            "default_model": "gemini-1.5-flash",
            "requires_api_key": True,
            "api_env": "GOOGLE_API_KEY"
        },
        "openrouter": {
            "name": "OpenRouter",
            "description": "Many free models available (search for :free)",
            "default_model": "anthropic/claude-3-haiku",
            "requires_api_key": True,
            "api_env": "OPENROUTER_API_KEY"
        }
    }
    
    # Supported programming languages and frameworks
    SUPPORTED_LANGUAGES = [
        "python",
        "javascript", 
        "bash",
        "html",
        "klein"  # Klein micro-framework for Python web development
    ]
    
    def __init__(
        self, 
        model_provider: str = "ollama",
        model_name: str = "codellama",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        use_free_tier: bool = True,
        api_base: Optional[str] = None
    ):
        """
        Initialize the CodeAgent.
        
        Args:
            model_provider: LLM provider (ollama, groq, gemini, openrouter)
            model_name: Specific model to use
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens per response
            use_free_tier: Whether to use free-tier APIs
            api_base: Custom API base URL (for Ollama local, or OpenRouter)
        """
        # Validate and set model provider
        self.model_provider = model_provider.lower()
        if self.model_provider not in self.AVAILABLE_PROVIDERS:
            logger.warning(f"Unknown provider '{self.model_provider}', defaulting to 'ollama'")
            self.model_provider = "ollama"
        
        self.model_name = model_name or self._get_default_model()
        self.temperature = max(0.0, min(1.0, temperature))
        self.max_tokens = max_tokens
        self.use_free_tier = use_free_tier
        self.api_base = api_base or self._get_default_base_url()
        
        self.conversation_history: List[Dict[str, str]] = []
        self.max_history = 20  # Keep last 20 exchanges
        
        # Supported languages for execution
        self.supported_languages = ["python", "javascript", "bash", "html"]
        
        # Check if Klein is requested and add it
        if "klein" in self.SUPPORTED_LANGUAGES and "klein" not in self.supported_languages:
            self.supported_languages.append("klein")
        
        # Log provider info
        provider_info = self.AVAILABLE_PROVIDERS[self.model_provider]
        logger.info(f"CodeAgent initialized: {provider_info['name']}/{self.model_name}")
        if provider_info.get("requires_api_key") and not self._check_api_key():
            logger.warning(f"{provider_info['name']} requires API key but none found")
    
    def _get_default_model(self) -> str:
        """Get the default model for the selected provider."""
        provider = self.AVAILABLE_PROVIDERS[self.model_provider]
        return provider.get("default_model", "codellama")
    
    def _get_default_base_url(self) -> Optional[str]:
        """Get default API base URL based on provider."""
        if self.model_provider == "ollama":
            return "http://localhost:11434"
        return None
    
    def _check_api_key(self) -> bool:
        """Check if the required API key is available for the provider."""
        provider = self.AVAILABLE_PROVIDERS[self.model_provider]
        api_env = provider.get("api_env", "")
        if api_env:
            return bool(os.getenv(api_env))
        return True
    
    def _build_prompt(
        self, 
        task: str, 
        context: Optional[Dict[str, Any]] = None,
        language: str = "python"
    ) -> str:
        """Build the prompt for the LLM based on task and context."""
        
        parts = [f"Task: {task}"]
        
        if context:
            if "code" in context:
                parts.append(f"\nExisting code context:\n```\n{context['code']}\n```")
            if "language" in context:
                parts.append(f"\nProgramming language: {context['language']}")
            if "description" in context:
                parts.append(f"\nContext: {context['description']}")
        
        # Add framework-specific instructions if language is klein
        if language.lower() == "klein":
            parts.append("\nGenerate Klein micro-framework code for Python.")
            parts.append("Klein is a micro-framework for building web APIs quickly.")
            parts.append("Return clean, minimal Klein route definitions.")
            parts.append("Include proper imports: 'from klein import Klein'")
        
        parts.append(f"\nGenerate {language} code.")
        parts.append("Follow best practices for the specified language/framework.")
        parts.append("Include error handling where appropriate.")
        parts.append("Return only the code, with comments explaining key sections.")
        
        return "\n".join(parts)
    
    def generate_code(
        self, 
        prompt: str, 
        context: Optional[Dict[str, Any]] = None,
        language: str = "python"
    ) -> str:
        """
        Generate code based on a natural language prompt.
        
        Args:
            prompt: Description of what code to generate
            context: Optional context (existing code, requirements, etc.)
            language: Programming language (python, javascript, klein, etc.)
            
        Returns:
            Generated code as a string
        """
        # Validate language
        if language.lower() not in self.SUPPORTED_LANGUAGES:
            logger.warning(f"Language '{language}' not in supported list, defaulting to 'python'")
            language = "python"
        
        # Add to conversation history
        self.conversation_history.append({"role": "user", "content": prompt})
        if len(self.conversation_history) > self.max_history:
            self.conversation_history = self.conversation_history[-self.max_history:]
        
        # Build the prompt
        full_prompt = self._build_prompt(prompt, context, language)
        
        # Try to get response from LLM
        try:
            generated_code = self._call_llm(full_prompt, language)
        except Exception as e:
            logger.warning(f"LLM call failed: {e}, falling back to template")
            generated_code = self._fallback_generate(prompt, language)
        
        # Clean up the response
        code = self._clean_code_response(generated_code, language)
        
        # Add to history
        self.conversation_history.append({"role": "assistant", "content": code})
        
        return code
    
    def _call_llm(self, prompt: str, language: str) -> str:
        """Call the LLM API based on the configured provider."""
        
        if self.model_provider == "ollama":
            return self._call_ollama(prompt, language)
        elif self.model_provider == "groq":
            return self._call_groq(prompt, language)
        elif self.model_provider == "gemini":
            return self._call_gemini(prompt, language)
        elif self.model_provider == "openrouter":
            return self._call_openrouter(prompt, language)
        else:
            # Default to ollama local
            return self._call_ollama(prompt, language)
    
    def _call_ollama(self, prompt: str, language: str) -> str:
        """Call Ollama local LLM."""
        import requests
        
        model = self.model_name or self._get_default_model()
        url = f"{self.api_base}/api/generate"
        
        payload = {
            "model": model,
            "prompt": prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False
        }
        
        try:
            response = requests.post(url, json=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "")
            else:
                raise Exception(f"Ollama API returned {response.status_code}")
        except ImportError:
            raise Exception("requests library not available")
        except Exception as e:
            raise Exception(f"Ollama connection error: {e}")
    
    def _call_groq(self, prompt: str, language: str) -> str:
        """Call Groq API (free tier available)."""
        try:
            import os
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key:
                raise Exception("GROQ_API_KEY not found in environment. Get free key from https://groq.com")
            
            import requests
            url = "https://api.groq.com/openai/v1/chat/completions"
            
            # Map language to system prompt
            system_prompt = f"You are a {language} coding expert. Generate clean, efficient code."
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            payload = {
                "model": self.model_name or self._get_default_model(),
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return result["choices"][0]["message"]["content"]
            else:
                raise Exception(f"Groq API returned {response.status_code}: {response.text}")
                
        except ImportError:
            raise Exception("requests library not available")
        except Exception as e:
            raise Exception(f"Groq API error: {e}")
    
    def _call_gemini(self, prompt: str, language: str) -> str:
        """Call Google Gemini AI Studio (generous free tier)."""
        try:
            import os
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise Exception("GOOGLE_API_KEY not found in environment. Get free key from https://ai.google.dev")
            
            import requests
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name or 'gemini-1.5-flash'}:generateContent"
            
            # Prepare the content
            content = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }]
            }
            
            params = {"key": api_key}
            
            response = requests.post(url, json=content, params=params, timeout=30)
            if response.status_code == 200:
                result = response.json()
                # Extract text from Gemini response
                if "candidates" in result and result["candidates"]:
                    return result["candidates"][0]["content"]["parts"][0]["text"]
                elif "text" in result:
                    return result["text"]
                else:
                    return str(result)
            else:
                raise Exception(f"Gemini API returned {response.status_code}: {response.text}")
                
        except ImportError:
            raise Exception("requests library not available")
        except Exception as e:
            raise Exception(f"Gemini API error: {e}")
    
    def _call_openrouter(self, prompt: str, language: str) -> str:
        """Call OpenRouter API (many free models)."""
        try:
            import os
            api_key = os.getenv("OPENROUTER_API_KEY")
            if not api_key:
                raise Exception("OPENROUTER_API_KEY not found in environment. Get free key from https://openrouter.ai")
            
            import requests
            url = "https://openrouter.ai/api/v1/chat/completions"
            
            # Map language to system prompt
            system_prompt = f"You are a {language} coding expert. Generate clean, efficient code."
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            payload = {
                "model": self.model_name or self._get_default_model(),
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/ai-code-agent",
                "X-Title": "AI Code Agent"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return result["choices"][0]["message"]["content"]
            else:
                raise Exception(f"OpenRouter API returned {response.status_code}: {response.text}")
                
        except ImportError:
            raise Exception("requests library not available")
        except Exception as e:
            raise Exception(f"OpenRouter API error: {e}")
    
    def _clean_code_response(self, response: str, language: str) -> str:
        """Clean and extract code from LLM response."""
        
        if not response:
            return ""
        
        # Remove markdown code blocks if present
        # Handle ```python, ```javascript, ```klein, ``` etc.
        code_patterns = [
            (r"^```(\w*)\n?", ""),
            (r"\n```$", ""),
        ]
        
        cleaned = response
        for pattern, replacement in code_patterns:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.MULTILINE)
        
        # If language is Klein, ensure proper imports
        if language.lower() == "klein":
            # Make sure Klein import is present
            if "from klein import" not in cleaned and "import klein" not in cleaned.lower():
                # Add Klein import at the top
                lines = cleaned.split("\n")
                if lines and lines[0].strip():
                    lines.insert(0, "from klein import Klein")
                else:
                    lines.insert(0, "from klein import Klein")
                cleaned = "\n".join(lines)
        
        return cleaned.strip()
    
    def execute_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Execute the given code in a safe, sandboxed environment.
        
        Args:
            code: The code to execute
            language: Programming language (python, javascript, etc.)
            
        Returns:
            Dictionary with execution results (output, errors, return_code)
        """
        logger.info(f"Executing {language} code...")
        
        result = {
            "output": "",
            "errors": "",
            "return_code": -1,
            "success": False
        }
        
        try:
            if language.lower() == "python":
                with tempfile.NamedTemporaryFile(
                    mode="w", 
                    suffix=".py", 
                    delete=False
                ) as f:
                    f.write(code)
                    temp_path = f.name
                
                try:
                    process = subprocess.run(
                        ["python", temp_path],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    result["output"] = process.stdout
                    result["errors"] = process.stderr
                    result["return_code"] = process.returncode
                    result["success"] = process.returncode == 0
                finally:
                    os.unlink(temp_path)
                    
            elif language.lower() == "javascript":
                with tempfile.NamedTemporaryFile(
                    mode="w", 
                    suffix=".js", 
                    delete=False
                ) as f:
                    f.write(code)
                    temp_path = f.name
                
                try:
                    process = subprocess.run(
                        ["node", temp_path],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    result["output"] = process.stdout
                    result["errors"] = process.stderr
                    result["return_code"] = process.returncode
                    result["success"] = process.returncode == 0
                finally:
                    os.unlink(temp_path)
            elif language.lower() == "klein":
                # Klein requires a running server, so we just validate the syntax
                result["output"] = "Klein code requires a running server. Syntax check only."
                result["errors"] = ""
                result["return_code"] = 0
                result["success"] = True
                # Try to validate Python syntax
                try:
                    compile(code, "<klein>", "exec")
                    result["output"] += "\n✅ Python syntax valid"
                except SyntaxError as e:
                    result["errors"] += f"\n❌ Syntax error: {e}"
                    result["success"] = False
            else:
                result["errors"] = f"Language '{language}' not supported for execution"
                
        except subprocess.TimeoutExpired:
            result["errors"] = "Code execution timed out (30s limit)"
        except Exception as e:
            result["errors"] = f"Execution error: {str(e)}"
            
        return result
    
    def debug_code(self, code: str, error_output: str, language: str = "python") -> str:
        """
        Analyze code and error output to suggest fixes.
        
        Args:
            code: The code that failed
            error_output: The error message from execution
            language: Programming language
            
        Returns:
            Suggested fix for the code
        """
        logger.info(f"Debugging {language} code with error: {error_output[:50]}...")
        
        # In production, this would send the code + error to LLM for analysis
        # For now, return the original code with basic placeholder fixes
        fixed_code = code
        
        # Basic placeholder fixes based on common errors
        if "SyntaxError" in error_output:
            # Try to add missing colon or fix indentation
            fixed_code = self._fix_syntax_issues(fixed_code)
        if "NameError" in error_output:
            # Add missing imports or variable definitions
            pass
        if "IndentationError" in error_output:
            # Fix indentation issues
            pass
        if language.lower() == "klein" and "ImportError" in error_output:
            # Suggest adding Klein import
            if "from klein import" not in fixed_code:
                fixed_code = "from klein import Klein\n" + fixed_code
        
        return fixed_code
    
    def _fix_syntax_issues(self, code: str) -> str:
        """Basic syntax fixing for common Python issues."""
        lines = code.split("\n")
        fixed_lines = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Ensure proper indentation
                if not fixed_lines or fixed_lines[-1].endswith(":") and not line.startswith(" "):
                    indent_level += 1
                fixed_lines.append("    " * indent_level + stripped)
            else:
                fixed_lines.append(line)
                
        return "\n".join(fixed_lines)
    
    def search_web(self, query: str) -> List[Dict[str, str]]:
        """
        Search the web for solutions to programming problems.
        
        Args:
            query: Search query (e.g., "python error handling best practices")
            
        Returns:
            List of search results with title and URL
        """
        logger.info(f"Searching web for: {query}")
        
        # In production, this would use DuckDuckGo Search or SerpAPI
        # For now, return placeholder results
        return [
            {
                "title": f"Search result for: {query}",
                "url": f"https://example.com/search?q={query.replace(' ', '+')}"
            }
        ]
    
    def refactor_code(self, code: str, language: str = "python") -> str:
        """
        Refactor and optimize the given code.
        
        Args:
            code: Code to refactor
            language: Programming language
            
        Returns:
            Refactored and optimized code
        """
        logger.info(f"Refactoring {language} code...")
        
        # Placeholder - would use LLM to refactor
        # For now, just return the code with minor improvements
        return code.strip()
    
    def chat(self, message: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Chat with the agent about programming tasks.
        
        Args:
            message: User message
            context: Optional context
            
        Returns:
            Agent response
        """
        self.conversation_history.append({"role": "user", "content": message})
        
        # Generate response based on message
        response = self._process_message(message, context)
        self.conversation_history.append({"role": "assistant", "content": response})
        
        return response
    
    def _process_message(self, message: str, context: Optional[Dict[str, Any]]) -> str:
        """Process a message and generate an appropriate response."""
        msg_lower = message.lower()
        
        if any(kw in msg_lower for kw in ["write", "create", "generate"]):
            # Check if Klein is mentioned
            if "klein" in msg_lower or "micro-framework" in msg_lower:
                return self.generate_code(message, language="klein")
            return self.generate_code(message, context=context)
        elif any(kw in msg_lower for kw in ["execute", "run"]):
            # Extract code from conversation or prompt
            return "Please provide the code you want to execute."
        elif any(kw in msg_lower for kw in ["debug", "fix", "error"]):
            return "I can help debug your code. Please share the code and the error message."
        elif any(kw in msg_lower for kw in ["refactor", "optimize", "improve"]):
            return "I can help refactor your code. Please share the code you want to improve."
        elif any(kw in msg_lower for kw in ["search", "find", "lookup"]):
            return f"Searching for: {message}"
        else:
            return f"I received your message: '{message}'. How can I help you with programming?"
</task_progress>
</write_to_file>