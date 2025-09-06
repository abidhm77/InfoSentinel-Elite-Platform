"""
Reinforcement Learning for Attack Path Selection

This module implements reinforcement learning algorithms to discover and optimize
attack paths in penetration testing scenarios.
"""

import numpy as np
import random
from typing import Dict, List, Tuple, Any, Optional
from .knowledge_graph import AttackKnowledgeGraph

class AttackPathEnvironment:
    """
    Reinforcement learning environment for attack path selection.
    
    This environment simulates a target system where an agent can perform
    various attack techniques to exploit vulnerabilities and achieve objectives.
    """
    
    def __init__(self, knowledge_graph: AttackKnowledgeGraph, target_config: Dict[str, Any]):
        """
        Initialize the attack path environment.
        
        Args:
            knowledge_graph: Knowledge graph containing attack techniques and vulnerabilities
            target_config: Configuration of the target system (services, vulnerabilities, etc.)
        """
        self.knowledge_graph = knowledge_graph
        self.target_config = target_config
        self.reset()
        
        # Define action space based on available attack techniques
        self.action_space = self._build_action_space()
        
        # Define observation space
        self.observation_space = {
            "discovered_services": [],
            "exploited_vulnerabilities": [],
            "current_access_level": "none",
            "detected_actions": []
        }
        
        # Define rewards
        self.rewards = {
            "discover_service": 5,
            "exploit_vulnerability": 20,
            "privilege_escalation": 50,
            "data_exfiltration": 100,
            "detection_penalty": -30,
            "failed_exploit": -10,
            "repeated_action": -5
        }
    
    def _build_action_space(self) -> List[Dict[str, Any]]:
        """
        Build the action space based on available attack techniques.
        
        Returns:
            List of possible actions (attack techniques)
        """
        actions = []
        
        # Get all attack techniques from the knowledge graph
        for node_id, data in self.knowledge_graph.graph.nodes(data=True):
            if data.get("type") == "attack_technique":
                actions.append({
                    "id": node_id,
                    "name": data.get("name"),
                    "description": data.get("description"),
                    "tactics": data.get("tactics", []),
                    "prerequisites": self._get_technique_prerequisites(node_id)
                })
        
        return actions
    
    def _get_technique_prerequisites(self, technique_id: str) -> List[str]:
        """
        Get prerequisites for an attack technique.
        
        Args:
            technique_id: ID of the attack technique
            
        Returns:
            List of prerequisite conditions
        """
        # This is a simplified implementation
        # In a real system, this would be more complex and based on the knowledge graph
        
        # Map some common techniques to prerequisites
        prerequisite_map = {
            "T1190": ["exposed_web_application"],
            "T1059": ["code_execution"],
            "T1210": ["network_access", "vulnerable_service"]
        }
        
        return prerequisite_map.get(technique_id, [])
    
    def reset(self) -> Dict[str, Any]:
        """
        Reset the environment to its initial state.
        
        Returns:
            Initial observation
        """
        self.current_state = {
            "discovered_services": [],
            "exploited_vulnerabilities": [],
            "access_level": "none",
            "detection_level": 0.0,
            "actions_taken": [],
            "step_count": 0
        }
        
        # Initialize with some discovered services based on target configuration
        if "exposed_services" in self.target_config:
            for service in self.target_config["exposed_services"]:
                if random.random() < 0.8:  # 80% chance to discover exposed services initially
                    self.current_state["discovered_services"].append(service)
        
        return self._get_observation()
    
    def _get_observation(self) -> Dict[str, Any]:
        """
        Get the current observation.
        
        Returns:
            Current observation of the environment
        """
        return {
            "discovered_services": self.current_state["discovered_services"].copy(),
            "exploited_vulnerabilities": self.current_state["exploited_vulnerabilities"].copy(),
            "current_access_level": self.current_state["access_level"],
            "detected_actions": [a for a in self.current_state["actions_taken"] 
                               if a.get("detected", False)]
        }
    
    def step(self, action_idx: int) -> Tuple[Dict[str, Any], float, bool, Dict[str, Any]]:
        """
        Take a step in the environment by performing an attack action.
        
        Args:
            action_idx: Index of the action to perform
            
        Returns:
            Tuple of (observation, reward, done, info)
        """
        if action_idx < 0 or action_idx >= len(self.action_space):
            raise ValueError(f"Invalid action index: {action_idx}")
        
        action = self.action_space[action_idx]
        reward = 0
        done = False
        info = {"action_result": ""}
        
        # Check if action prerequisites are met
        prerequisites_met = self._check_prerequisites(action["prerequisites"])
        
        # Check if action has already been taken
        action_already_taken = any(a["id"] == action["id"] for a in self.current_state["actions_taken"])
        
        if action_already_taken:
            reward += self.rewards["repeated_action"]
            info["action_result"] = "Action already performed"
        elif not prerequisites_met:
            reward += self.rewards["failed_exploit"]
            info["action_result"] = "Prerequisites not met"
        else:
            # Action can be performed
            success_probability = self._calculate_success_probability(action)
            detection_probability = self._calculate_detection_probability(action)
            
            # Determine if action succeeds
            action_succeeds = random.random() < success_probability
            
            # Determine if action is detected
            action_detected = random.random() < detection_probability
            
            # Record the action
            self.current_state["actions_taken"].append({
                "id": action["id"],
                "name": action["name"],
                "step": self.current_state["step_count"],
                "succeeded": action_succeeds,
                "detected": action_detected
            })
            
            if action_detected:
                self.current_state["detection_level"] += 0.1
                reward += self.rewards["detection_penalty"]
                info["action_result"] += "Action was detected. "
            
            if action_succeeds:
                # Apply action effects
                effects = self._apply_action_effects(action)
                reward += effects["reward"]
                info["action_result"] += effects["result"]
                
                # Check if objective is achieved
                if self._check_objective_achieved():
                    reward += 100  # Bonus for achieving objective
                    done = True
                    info["action_result"] += "Objective achieved! "
            else:
                reward += self.rewards["failed_exploit"]
                info["action_result"] += "Action failed. "
        
        # Increment step count
        self.current_state["step_count"] += 1
        
        # Check if maximum detection level is reached
        if self.current_state["detection_level"] >= 0.7:
            done = True
            reward -= 50  # Penalty for being detected too much
            info["action_result"] += "Operation compromised due to high detection! "
        
        # Check if maximum steps reached
        if self.current_state["step_count"] >= 50:
            done = True
            info["action_result"] += "Maximum steps reached. "
        
        return self._get_observation(), reward, done, info
    
    def _check_prerequisites(self, prerequisites: List[str]) -> bool:
        """
        Check if prerequisites for an action are met.
        
        Args:
            prerequisites: List of prerequisite conditions
            
        Returns:
            True if all prerequisites are met, False otherwise
        """
        for prereq in prerequisites:
            if prereq == "exposed_web_application":
                if not any("web" in s for s in self.current_state["discovered_services"]):
                    return False
            elif prereq == "code_execution":
                if self.current_state["access_level"] not in ["user", "admin"]:
                    return False
            elif prereq == "network_access":
                if not self.current_state["discovered_services"]:
                    return False
            elif prereq == "vulnerable_service":
                if not self.current_state["exploited_vulnerabilities"]:
                    return False
        
        return True
    
    def _calculate_success_probability(self, action: Dict[str, Any]) -> float:
        """
        Calculate the probability of an action succeeding.
        
        Args:
            action: The action to perform
            
        Returns:
            Probability of success (0.0 to 1.0)
        """
        # Base success probability
        base_probability = 0.7
        
        # Adjust based on action complexity
        if "initial_access" in action.get("tactics", []):
            base_probability -= 0.1
        elif "privilege_escalation" in action.get("tactics", []):
            base_probability -= 0.2
        
        # Adjust based on target configuration
        if "security_level" in self.target_config:
            if self.target_config["security_level"] == "high":
                base_probability -= 0.2
            elif self.target_config["security_level"] == "low":
                base_probability += 0.1
        
        # Ensure probability is within valid range
        return max(0.1, min(0.9, base_probability))
    
    def _calculate_detection_probability(self, action: Dict[str, Any]) -> float:
        """
        Calculate the probability of an action being detected.
        
        Args:
            action: The action to perform
            
        Returns:
            Probability of detection (0.0 to 1.0)
        """
        # Base detection probability
        base_probability = 0.3
        
        # Adjust based on action stealth
        if "discovery" in action.get("tactics", []):
            base_probability -= 0.1
        elif "execution" in action.get("tactics", []):
            base_probability += 0.2
        
        # Adjust based on target configuration
        if "monitoring_level" in self.target_config:
            if self.target_config["monitoring_level"] == "high":
                base_probability += 0.2
            elif self.target_config["monitoring_level"] == "low":
                base_probability -= 0.1
        
        # Ensure probability is within valid range
        return max(0.1, min(0.9, base_probability))
    
    def _apply_action_effects(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply the effects of a successful action.
        
        Args:
            action: The action that was performed
            
        Returns:
            Dictionary with reward and result information
        """
        result = ""
        reward = 0
        
        # Apply effects based on action tactics
        tactics = action.get("tactics", [])
        
        if "discovery" in tactics:
            # Discover new services
            new_services = self._discover_new_services()
            if new_services:
                self.current_state["discovered_services"].extend(new_services)
                reward += self.rewards["discover_service"] * len(new_services)
                result += f"Discovered {len(new_services)} new services. "
        
        if "initial_access" in tactics or "execution" in tactics:
            # Exploit vulnerabilities
            exploited = self._exploit_vulnerabilities(action["id"])
            if exploited:
                self.current_state["exploited_vulnerabilities"].append(exploited)
                reward += self.rewards["exploit_vulnerability"]
                result += f"Exploited vulnerability: {exploited}. "
                
                # Gain initial access if we don't have it yet
                if self.current_state["access_level"] == "none":
                    self.current_state["access_level"] = "user"
                    result += "Gained user access. "
        
        if "privilege_escalation" in tactics:
            # Attempt privilege escalation
            if self.current_state["access_level"] == "user" and len(self.current_state["exploited_vulnerabilities"]) >= 2:
                self.current_state["access_level"] = "admin"
                reward += self.rewards["privilege_escalation"]
                result += "Privilege escalation successful! Gained admin access. "
        
        if "exfiltration" in tactics:
            # Attempt data exfiltration
            if self.current_state["access_level"] in ["user", "admin"]:
                reward += self.rewards["data_exfiltration"]
                result += "Successfully exfiltrated sensitive data. "
        
        return {"reward": reward, "result": result}
    
    def _discover_new_services(self) -> List[str]:
        """
        Discover new services in the target system.
        
        Returns:
            List of newly discovered services
        """
        new_services = []
        
        # Get all possible services from target configuration
        all_services = self.target_config.get("all_services", [])
        
        # Filter out already discovered services
        undiscovered = [s for s in all_services if s not in self.current_state["discovered_services"]]
        
        # Randomly discover some new services
        num_to_discover = min(len(undiscovered), random.randint(1, 3))
        if undiscovered and num_to_discover > 0:
            new_services = random.sample(undiscovered, num_to_discover)
        
        return new_services
    
    def _exploit_vulnerabilities(self, technique_id: str) -> Optional[str]:
        """
        Attempt to exploit vulnerabilities using an attack technique.
        
        Args:
            technique_id: ID of the attack technique
            
        Returns:
            ID of the exploited vulnerability, or None if no vulnerability was exploited
        """
        # Get vulnerabilities that can be exploited by this technique
        exploitable_vulnerabilities = []
        
        for _, target, data in self.knowledge_graph.graph.out_edges(technique_id, data=True):
            if data.get("type") == "exploits":
                target_data = self.knowledge_graph.graph.nodes[target]
                if target_data.get("type") == "vulnerability":
                    # Check if vulnerability exists in target system
                    if target in self.target_config.get("vulnerabilities", []):
                        # Check if not already exploited
                        if target not in self.current_state["exploited_vulnerabilities"]:
                            exploitable_vulnerabilities.append(target)
        
        # Randomly select one vulnerability to exploit
        if exploitable_vulnerabilities:
            return random.choice(exploitable_vulnerabilities)
        
        return None
    
    def _check_objective_achieved(self) -> bool:
        """
        Check if the penetration testing objective has been achieved.
        
        Returns:
            True if objective is achieved, False otherwise
        """
        objective = self.target_config.get("objective", "admin_access")
        
        if objective == "admin_access":
            return self.current_state["access_level"] == "admin"
        elif objective == "data_exfiltration":
            return self.current_state["access_level"] in ["user", "admin"] and \
                   any("exfiltration" in a.get("tactics", []) for a in self.current_state["actions_taken"] 
                       if a.get("succeeded", False))
        
        return False


class QAgent:
    """
    Q-learning agent for attack path selection.
    """
    
    def __init__(self, env: AttackPathEnvironment, learning_rate: float = 0.1, 
                 discount_factor: float = 0.99, exploration_rate: float = 1.0,
                 exploration_decay: float = 0.995, min_exploration_rate: float = 0.01):
        """
        Initialize the Q-learning agent.
        
        Args:
            env: Attack path environment
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
            exploration_rate: Initial exploration rate (epsilon)
            exploration_decay: Rate at which exploration rate decays
            min_exploration_rate: Minimum exploration rate
        """
        self.env = env
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.exploration_decay = exploration_decay
        self.min_exploration_rate = min_exploration_rate
        
        # Initialize Q-table
        self.q_table = {}
    
    def _get_state_key(self, observation: Dict[str, Any]) -> str:
        """
        Convert an observation to a state key for the Q-table.
        
        Args:
            observation: Environment observation
            
        Returns:
            String key representing the state
        """
        # Create a simplified state representation
        services = sorted(observation["discovered_services"])
        vulnerabilities = sorted(observation["exploited_vulnerabilities"])
        access_level = observation["current_access_level"]
        
        # Create a string key
        key = f"services:{','.join(services)}|vulns:{','.join(vulnerabilities)}|access:{access_level}"
        
        return key
    
    def _get_q_values(self, state_key: str) -> np.ndarray:
        """
        Get Q-values for a state.
        
        Args:
            state_key: Key representing the state
            
        Returns:
            Array of Q-values for each action
        """
        if state_key not in self.q_table:
            # Initialize Q-values for new state
            self.q_table[state_key] = np.zeros(len(self.env.action_space))
        
        return self.q_table[state_key]
    
    def choose_action(self, observation: Dict[str, Any]) -> int:
        """
        Choose an action based on the current observation.
        
        Args:
            observation: Environment observation
            
        Returns:
            Index of the chosen action
        """
        state_key = self._get_state_key(observation)
        q_values = self._get_q_values(state_key)
        
        # Epsilon-greedy action selection
        if random.random() < self.exploration_rate:
            # Explore: choose a random action
            return random.randint(0, len(self.env.action_space) - 1)
        else:
            # Exploit: choose the best action
            return np.argmax(q_values)
    
    def learn(self, state: Dict[str, Any], action: int, reward: float, 
              next_state: Dict[str, Any], done: bool) -> None:
        """
        Update Q-values based on experience.
        
        Args:
            state: Current state observation
            action: Action taken
            reward: Reward received
            next_state: Next state observation
            done: Whether the episode is done
        """
        state_key = self._get_state_key(state)
        next_state_key = self._get_state_key(next_state)
        
        # Get current Q-value
        q_values = self._get_q_values(state_key)
        current_q = q_values[action]
        
        # Get next max Q-value
        next_q_values = self._get_q_values(next_state_key)
        max_next_q = np.max(next_q_values) if not done else 0
        
        # Q-learning update
        new_q = current_q + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q)
        q_values[action] = new_q
        
        # Update exploration rate
        self.exploration_rate = max(self.min_exploration_rate, 
                                   self.exploration_rate * self.exploration_decay)
    
    def train(self, num_episodes: int = 1000) -> List[float]:
        """
        Train the agent.
        
        Args:
            num_episodes: Number of episodes to train for
            
        Returns:
            List of total rewards for each episode
        """
        rewards_history = []
        
        for episode in range(num_episodes):
            state = self.env.reset()
            total_reward = 0
            done = False
            
            while not done:
                # Choose action
                action = self.choose_action(state)
                
                # Take action
                next_state, reward, done, _ = self.env.step(action)
                
                # Learn from experience
                self.learn(state, action, reward, next_state, done)
                
                # Update state and reward
                state = next_state
                total_reward += reward
            
            rewards_history.append(total_reward)
            
            # Print progress
            if (episode + 1) % 100 == 0:
                avg_reward = np.mean(rewards_history[-100:])
                print(f"Episode {episode + 1}/{num_episodes}, Avg Reward: {avg_reward:.2f}, "
                      f"Exploration Rate: {self.exploration_rate:.4f}")
        
        return rewards_history
    
    def get_optimal_attack_path(self, initial_observation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get the optimal attack path based on learned Q-values.
        
        Args:
            initial_observation: Initial environment observation
            
        Returns:
            List of actions forming the optimal attack path
        """
        state = initial_observation
        done = False
        path = []
        
        while not done:
            state_key = self._get_state_key(state)
            q_values = self._get_q_values(state_key)
            
            # Choose best action
            action_idx = np.argmax(q_values)
            action = self.env.action_space[action_idx]
            
            # Add action to path
            path.append({
                "id": action["id"],
                "name": action["name"],
                "description": action["description"],
                "q_value": q_values[action_idx]
            })
            
            # Take action
            next_state, _, done, info = self.env.step(action_idx)
            
            # Update state
            state = next_state
            
            # Prevent infinite loops
            if len(path) >= 20:
                break
        
        return path


# Example usage
if __name__ == "__main__":
    from knowledge_graph import AttackKnowledgeGraph
    
    # Create knowledge graph
    kg = AttackKnowledgeGraph()
    
    # Define target configuration
    target_config = {
        "name": "Example Corp Web Server",
        "exposed_services": ["http", "https", "ssh"],
        "all_services": ["http", "https", "ssh", "mysql", "smb", "ldap"],
        "vulnerabilities": ["CVE-2021-44228", "CVE-2021-26084"],
        "security_level": "medium",
        "monitoring_level": "medium",
        "objective": "admin_access"
    }
    
    # Create environment
    env = AttackPathEnvironment(kg, target_config)
    
    # Create agent
    agent = QAgent(env)
    
    # Train agent
    rewards = agent.train(num_episodes=500)
    
    # Get optimal attack path
    initial_observation = env.reset()
    optimal_path = agent.get_optimal_attack_path(initial_observation)
    
    print("\nOptimal Attack Path:")
    for i, action in enumerate(optimal_path):
        print(f"{i+1}. {action['name']} (Q-value: {action['q_value']:.2f})")
        print(f"   {action['description']}")