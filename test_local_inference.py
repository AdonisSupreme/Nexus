import torch
from ollama import LLMModel

# Load the model
model = LLMModel.load("path/to/downloaded/mistral-7b-instruct")

def generate_response(prompt):
    # Prepare inputs for the model
    input_ids = torch.tensor([model.tokenizer.encode(prompt, add_special_tokens=True)])

    # Set number of samples (top_k or top_p) and temperature
    num_samples = 1
    top_k = 50
    top_p = 0.95
    temperature = 0.7

    # Generate output from the model
    with torch.no_grad():
        outputs = model(input_ids, max_new_tokens=200, num_samples=num_samples, top_k=top_k, top_p=top_p, temperature=temperature)
        generated_text = model.tokenizer.decode(outputs[0].ids)

    return generated_text

# Test the model
prompt = "Tell me a funny joke."
response = generate_response(prompt)
print(f"Prompt: {prompt}\nResponse: {response}")
