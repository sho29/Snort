import React, { useState, useEffect } from "react";
import axios from "axios";
import RuleOutput from "./RuleOutput";

const RuleForm = () => {
  const [generatedRule, setGeneratedRule] = useState("");

  const [formWidth, setFormWidth] = useState(getWidth());

  function getWidth() {
    return window.innerWidth < 768 ? "90%" : "1000px";
  }

  useEffect(() => {
    const handleResize = () => {
      setFormWidth(getWidth());
    };

    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const [formData, setFormData] = useState({
    alertType: "alert",
    protocol: "tcp",
    srcIP: "any",
    srcPort: "any",
    dstIP: "any",
    dstPort: "80",
    direction: "->",
    message: "",
    sid: "",
    priority: "",
    classtype: "web-attack",
    reference: "url,www.example.com",
    flow: "to_server,established",
    flags: "S",
    content: "",
    nocase: false,
    depth: "",
    offset: "",
    distance: "",
    within: "",
    http_uri: false,
    http_method: "",
    http_header: "",
    dns_query: "",
    dsize: "",
    threshold: "",
    pcre: "",
    pcreCaseInsensitive: false,
  });

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === "checkbox" ? checked : value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://localhost:8080/generate-rule", formData);
      setGeneratedRule(response.data.rule);
    } catch (error) {
      console.error("Error generating rule:", error);
    }
  };

  return (
    <div className="center-container">
      <div className="card" style={{ width: formWidth }}>
        <h2 className="text-center">Snort Rule Generator</h2>
        <form onSubmit={handleSubmit}>
          {/* Row 1: Action, Protocol, Direction */}
          <div className="form-group">
            <div>
              <label>Action</label>
              <select name="alertType" value={formData.alertType} onChange={handleChange}>
                <option value="alert">Alert</option>
                <option value="log">Log</option>
                <option value="pass">Pass</option>
                <option value="drop">Drop</option>
                <option value="reject">Reject</option>
                <option value="sdrop">Sdrop</option>
              </select>
            </div>
            <div>
              <label>Protocol</label>
              <select name="protocol" value={formData.protocol} onChange={handleChange}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="ip">IP</option>
              </select>
            </div>
            <div>
              <label>Direction</label>
              <select name="direction" value={formData.direction} onChange={handleChange}>
                <option value="->">Unidirectional (→)</option>
                <option value="<->">Bidirectional (↔)</option>
              </select>
            </div>
          </div>

          {/* Row 2: Source & Destination IP and ports */}
          <div className="form-group">
            <div>
              <label>Source IP</label>
              <input type="text" name="srcIP" value={formData.srcIP} onChange={handleChange} />
            </div>
            <div>
              <label>Destination IP</label>
              <input type="text" name="dstIP" value={formData.dstIP} onChange={handleChange} />
            </div>
            <div>
              <label>Source Port</label>
              <input type="text" name="srcPort" value={formData.srcPort} onChange={handleChange} />
            </div>
            <div>
              <label>Destination Port</label>
              <input type="text" name="dstPort" value={formData.dstPort} onChange={handleChange} />
            </div>
          </div>

          {/* Row 3: Message, SID, Priority */}
          <div className="form-group">
            <div>
              <label>Message</label>
              <input type="text" name="message" value={formData.message} onChange={handleChange} style={{width: "90%"}}/>
            </div>
            <div>
              <label>SID</label>
              <input type="text" name="sid" value={formData.sid} onChange={handleChange} />
            </div>
            <div>
              <label>Priority</label>
              <input type="text" name="priority" value={formData.priority} onChange={handleChange} />
            </div>
          </div>

          {/* Row 4: Advanced Options */}
          <div className="form-group">
            <div>
              <label>Flow</label>
              <input type="text" name="flow" value={formData.flow} onChange={handleChange} style={{width: "90%"}}/>
            </div>
            <div>
              <label>Flags</label>
              <input type="text" name="flags" value={formData.flags} onChange={handleChange} />
            </div>
            <div>
              <label>Content</label>
              <input type="text" name="content" value={formData.content} onChange={handleChange} />
            </div>
            <div className="checkbox-container">
            <label>
                <input type="checkbox" name="nocase" checked={formData.nocase} onChange={handleChange} />
                Case Insensitive (Content)
            </label>
            </div>
          </div>

          {/* <div className="form-group">
            <div>
              <label>Content</label>
              <input type="text" name="content" value={formData.content} onChange={handleChange} />
            </div>
            <div>
              <label>
                <input type="checkbox" name="nocase" checked={formData.nocase} onChange={handleChange} />
                Case Insensitive
              </label>
            </div>
          </div> */}

          {/* Row 5: HTTP & DNS */}
          <div className="form-group">
            <div>
              <label>HTTP Method</label>
              <input type="text" name="http_method" value={formData.http_method} onChange={handleChange} style={{width: "60%"}}/>
            </div>
            <div>
              <label>DNS Query</label>
              <input type="text" name="dns_query" value={formData.dns_query} onChange={handleChange} style={{width: "60%"}}/>
            </div>
          </div>
          <div className="form-group">
          <div>
            <label>Regular Expression</label>
            <input type="text" name="pcre" value={formData.pcre} onChange={handleChange} placeholder="/sql.*select/i" />
          </div>
          <div className="checkbox-container">
            <label>
              <input type="checkbox" name="pcreCaseInsensitive" checked={formData.pcreCaseInsensitive} onChange={handleChange} />
              Case Insensitive (Regex)
            </label>
          </div>
          </div>
          <button type="submit">Generate Rule</button>
        </form>
        <RuleOutput rule={generatedRule} />
      </div>
    </div>
  );
};

export default RuleForm;
