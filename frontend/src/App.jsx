import { useState } from "react";
import RuleForm from "./components/RuleForm";

function App() {
  const [generatedRule, setGeneratedRule] = useState("");

  return (
    <div>
      <RuleForm setGeneratedRule={setGeneratedRule} />
    </div>
  );
}

export default App;
