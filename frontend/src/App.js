import React, { useState } from "react";
import RuleForm from "./components/RuleForm";
import RuleOutput from "./components/RuleOutput";

function App() {
  const [generatedRule, setGeneratedRule] = useState("");

  return (
    <div>
      <RuleForm setGeneratedRule={setGeneratedRule} />
    </div>
  );
}

export default App;
