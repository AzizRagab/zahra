"""Test script for the ZahraController."""
from core.zahra_controller import ZahraController, get_controller, reset_controller
from core.zahra_config import ZahraConfig, is_llama_model, select_non_llama_model

# Test 1: LLaMA rejection
print("=== Test 1: LLaMA Rejection ===")
print("is_llama_model('meta-llama/Llama-2-7b-chat-hf'):", is_llama_model("meta-llama/Llama-2-7b-chat-hf"))
print("is_llama_model('mistralai/Mistral-7B-Instruct-v0.2'):", is_llama_model("mistralai/Mistral-7B-Instruct-v0.2"))
print("is_llama_model('vicuna-13b'):", is_llama_model("vicuna-13b"))
print("is_llama_model('alpaca-7b'):", is_llama_model("alpaca-7b"))
safe = select_non_llama_model("meta-llama/Llama-2-7b-chat-hf")
print("select_non_llama_model(llama):", safe)
print()

# Test 2: Create controller instance
print("=== Test 2: ZahraController Instance ===")
reset_controller()
ctrl = get_controller()
print("Name:", ctrl.name)
print("Version:", ctrl.version)
print("Attribution:", ctrl.attribution)
print("Mode:", ctrl.mode)
print("Running:", ctrl.running)
print("Model:", ctrl.ensure_non_llama_model())
print("Is offline:", ctrl.llm.is_offline)
print("No LLaMA:", not is_llama_model(ctrl.llm.config.model or ""))
print()

# Test 3: Controller status
print("=== Test 3: Controller Status ===")
status = ctrl.status()
print("Status keys:", list(status.keys()))
print("Controller name:", status["name"])
print("Mode:", status["mode"])
print("No LLaMA:", status["no_llama"])
print("Agents:", status["agents"])
print("Campaigns:", status["campaigns"])
print("Budget unlimited:", status["budget"]["unlimited"])
print()

# Test 4: Decide
print("=== Test 4: Strategic Decision ===")
decision = ctrl.decide("recon example.com")
print("Intent:", decision["intent"])
print("Target:", decision["target"])
print("Agents:", decision["agents"])
print("Plan:")
for i, step in enumerate(decision["plan"], 1):
    print(f"  {i}. {step}")
print()

# Test 5: Run a command
print("=== Test 5: Run Command ===")
result = ctrl.run_command("echo hello from zahra")
print("Return code:", result["return_code"])
print("Stdout:", result["stdout"].strip())
print()

ctrl.stop()
print("=== ALL TESTS PASSED ===")
