import requests
import json
import time

BASE_URL = "https://lkjhgfdsaqwertyu-csc26.cybersecuritychallenge.al"

# Storage
collected_data = {}  # request_id -> full response
all_responses = []
flag_parts = {}

session = requests.Session()

def fetch_data():
    """Fetch and store data from /data endpoint."""
    try:
        resp = session.get(f"{BASE_URL}/data", timeout=10)
        data = resp.json()
        
        # Store by request_id for lookup
        if "request_id" in data:
            collected_data[data["request_id"]] = data
        
        all_responses.append(data)
        return data
    except Exception as e:
        return {"error": str(e)}

def answer_question(question_id, answer):
    """Submit answer to memory question."""
    try:
        resp = session.get(
            f"{BASE_URL}/answer",
            params={"question_id": question_id, "answer": str(answer)},
            timeout=10
        )
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def parse_and_answer(data):
    """Parse question from response and answer it."""
    question = data.get("question", "")
    question_id = data.get("question_id")
    
    if not question or not question_id:
        return None
    
    # Extract request_id from question
    # Format: "What was the <field> in request <request_id>?"
    import re
    match = re.search(r'request (\d+)', question)
    if not match:
        return None
    
    target_request_id = int(match.group(1))
    
    # Find which field is being asked about
    fields = ["color", "city", "animal", "pattern", "hash", 
              "random_number", "random_string", "data_type"]
    
    for field in fields:
        if field in question.lower():
            # Look up the stored data
            if target_request_id in collected_data:
                stored_data = collected_data[target_request_id]
                if field in stored_data:
                    answer = stored_data[field]
                    result = answer_question(question_id, answer)
                    return result
    
    return None

def extract_flag_part(data):
    """Extract flag part from special_data field."""
    special = data.get("special_data", "")
    if "Flag part" in special:
        # Format: "Flag part X of 5: Flag part X: 'VALUE'"
        import re
        match = re.search(r'Flag part (\d+) of \d+:.*?[\'"](.+?)[\'"]', special)
        if match:
            part_num = int(match.group(1))
            part_value = match.group(2)
            flag_parts[part_num] = part_value
            return part_num, part_value
    return None

def solve():
    print("=== Mind Palace Solver ===")
    print(f"Base URL: {BASE_URL}\n")
    
    # Check initial stats
    stats = session.get(f"{BASE_URL}/stats").json()
    print(f"Initial stats: {json.dumps(stats, indent=2)}\n")
    
    # Main loop: collect data and answer questions
    for i in range(200):
        print(f"[{i+1}/200] Fetching data...")
        data = fetch_data()
        
        # Check for errors
        if "error" in data:
            print(f"  [!] Error: {data['error']}")
            continue
        
        # Display basic info
        if "request_id" in data:
            req_id = data.get("request_id")
            data_type = data.get("data_type", "")
            seq = data.get("sequence", "")
            print(f"  req_id={req_id}, type={data_type}, seq={seq}")
        
        # Check for flag parts
        flag_info = extract_flag_part(data)
        if flag_info:
            print(f"  [FLAG] Flag part {flag_info[0]} of 5: {flag_info[1]}")
        
        # Check for memory questions
        if "question" in data:
            q = data.get("question", "")
            qid = data.get("question_id", "")
            print(f"  [QUESTION] ID:{qid} - {q}")
            
            # Try to answer
            result = parse_and_answer(data)
            if result:
                print(f"  [ANSWER] {json.dumps(result)}")
                if result.get("status") == "success":
                    # Check if this revealed a flag part
                    time.sleep(0.5)
                    next_data = fetch_data()
                    flag_info = extract_flag_part(next_data)
                    if flag_info:
                        print(f"  [FLAG] Flag part {flag_info[0]} of 5: {flag_info[1]}")
        
        time.sleep(0.3)
    
    # Final stats
    print("\n" + "="*60)
    stats = session.get(f"{BASE_URL}/stats").json()
    print(f"Final stats: {json.dumps(stats, indent=2)}\n")
    
    # Reconstruct flag
    print("=== FLAG RECONSTRUCTION ===")
    for i in range(1, 6):
        if i in flag_parts:
            print(f"  Part {i}: {flag_parts[i]}")
    
    flag = "".join(flag_parts.get(i, "") for i in range(1, 6))
    print(f"\nReconstructed flag: {flag}")

if __name__ == "__main__":
    solve()
