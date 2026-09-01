"""
Programming Code Agent - UI Module
Provides interface for interacting with the code agent.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from typing import Optional

class CodeAgentUI:
    """Simple Tkinter-based interface for the CodeAgent."""
    
    def __init__(self, agent: 'CodeAgent', root: Optional[tk.Tk] = None):
        self.agent = agent
        self.root = root or tk.Tk()
        self._setup_main_window()
        
    def _setup_main_window(self):
        self.root.title("AI Code Agent")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input area
        input_frame = ttk.LabelFrame(main_frame, text="Request", padding="5")
        input_frame.pack(fill=tk.X, pady=5)
        
        self.input_text = tk.Text(input_frame, height=3, wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, side=tk.TOP)
        self.input_text.insert("1.0", "Enter your programming task...")
        
        # Buttons frame
        btn_frame = ttk.Frame(input_frame, padding="5")
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Generate Code", command=self._on_generate).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Execute", command=self._on_execute).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Debug", command=self._on_debug).pack(side=tk.LEFT, padx=2)
        
        # Output area
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.insert("1.0", "Agent output will appear here...\n")
        self.output_text.config(state=tk.DISABLED)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=5)
    
    def _on_generate(self):
        """Handle generate code button click."""
        prompt = self.input_text.get("1.0", tk.END).strip()
        if not prompt or prompt == "Enter your programming task...":
            self.status_var.set("Please enter a task")
            return
        
        self.status_var.set("Generating code...")
        self.root.update()
        
        code = self.agent.generate_code(prompt)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", code)
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set("Code generated")
    
    def _on_execute(self):
        """Handle execute code button click."""
        code = self.output_text.get("1.0", tk.END).strip()
        if not code:
            self.status_var.set("No code to execute")
            return
        
        self.status_var.set("Executing code...")
        self.root.update()
        
        result = self.agent.execute_code(code)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        
        if result["success"]:
            self.output_text.insert("1.0", "✅ Execution successful!\n\n")
            self.output_text.insert(tk.END, result["output"])
            if result["errors"]:
                self.output_text.insert(tk.END, "\n⚠️ Warnings:\n" + result["errors"])
        else:
            self.output_text.insert("1.0", "❌ Execution failed:\n")
            self.output_text.insert(tk.END, result["errors"])
            if result["output"]:
                self.output_text.insert(tk.END, "\nOutput:\n" + result["output"])
        
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set("Execution complete")
    
    def _on_debug(self):
        """Handle debug button click."""
        code = self.output_text.get("1.0", tk.END).strip()
        if not code:
            self.status_var.set("No code to debug")
            return
        
        # Get any previous error or prompt user for error
        error = self._get_error_input()
        if not error:
            return
            
        self.status_var.set("Debugging...")
        self.root.update()
        
        fixed_code = self.agent.debug_code(code, error)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", fixed_code)
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set("Debug complete")
    
    def _get_error_input(self) -> str:
        """Get error input from user."""
        err_win = tk.Toplevel(self.root)
        err_win.title("Enter Error Message")
        err_win.geometry("400x150")
        
        ttk.Label(err_win, text="Paste the error message:").pack(pady=5)
        err_text = tk.Text(err_win, height=3, wrap=tk.WORD)
        err_text.pack(fill=tk.X, padx=10)
        err_text.insert("1.0", "")
        
        def on_submit():
            nonlocal error
            error = err_text.get("1.0", tk.END).strip()
            err_win.destroy()
        
        ttk.Button(err_win, text="Debug", command=on_submit).pack(pady=5)
        
        self.root.wait_window(err_win)
        return error
    
    def run(self):
        """Start the UI main loop."""
        self.root.mainloop()
</task_progress>
</write_to_file>