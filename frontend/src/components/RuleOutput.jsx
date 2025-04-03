import React from "react";
const RuleOutput = ({ rule }) => {
    return (
      <div>
        <h3>Generated Snort Rule:</h3>
        <pre>{rule}</pre>
      </div>
    );
  };
  
  export default RuleOutput;
  