import React, { useEffect, useRef } from 'react';

export const HeaderWithAnimatedXYZ = ({ fullUrl }) => {
  const xyzRef = useRef(null);
  const effects = ['behind-bars', 'locked', 'blurred', 'plain'];

  useEffect(() => {
    let current = 0;
    const interval = setInterval(() => {
      if (xyzRef.current) {
        xyzRef.current.className = `xyz-cycle ${effects[current % effects.length]}`;
        current++;
      }
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header>
      <h1 className="upload-url">
        🚀 Sending <span ref={xyzRef} className="xyz-cycle plain">XYZ</span> to <span className="highlighted-url">{fullUrl}</span>
      </h1>
    </header>
  );
};
