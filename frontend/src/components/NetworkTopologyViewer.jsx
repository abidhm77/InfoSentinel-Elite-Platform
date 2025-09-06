import React, { useRef, useState } from 'react';
import { Canvas } from '@react-three/fiber';
import { Physics, useSphere, useBox } from '@react-three/cannon';
import { OrbitControls, Text } from '@react-three/drei';
import { Vector3 } from 'three';

function Node({ position, name, vulnerable, onClick }) {
  const [ref] = useSphere(() => ({
    position,
    mass: 1,
    args: [0.7], // Increased for better touch targets
  }));

  return (
    <mesh ref={ref} onClick={onClick}>
      <sphereGeometry args={[0.7, 32, 32]} />
      <meshStandardMaterial color={vulnerable ? 'red' : 'blue'} />
      <Text position={[0, 0.8, 0]} fontSize={0.4} color="white">
        {name}
      </Text>
    </mesh>
  );
}

function Edge({ start, end }) {
  const [ref] = useBox(() => ({
    position: [
      (start[0] + end[0]) / 2,
      (start[1] + end[1]) / 2,
      (start[2] + end[2]) / 2,
    ],
    scale: [0.1, 0.1, start.distanceTo(end)],
    rotation: [0, 0, Math.atan2(end[1] - start[1], end[0] - start[0])],
    type: 'Static',
  }));

  return (
    <mesh ref={ref}>
      <boxGeometry />
      <meshStandardMaterial color="white" />
    </mesh>
  );
}

export default function NetworkTopologyViewer({ networkData }) {
  const nodesWithPositions = networkData.nodes.map(node => ({
    ...node,
    position: [Math.random() * 10 - 5, Math.random() * 10 - 5, Math.random() * 10 - 5],
  }));

  // Simple edges: connect all to central (id 1)
  const edges = networkData.nodes
    .filter(node => node.id !== 1)
    .map(node => ({
      start: new Vector3(...nodesWithPositions.find(n => n.id === 1).position),
      end: new Vector3(...nodesWithPositions.find(n => n.id === node.id).position),
    }));

  const [selectedNode, setSelectedNode] = useState(null);

  return (
    <div className="glass-strong p-6 rounded-2xl h-96 gesture-area"> // Added gesture-area class for touch actions
      <Canvas>
        <ambientLight intensity={0.5} />
        <pointLight position={[10, 10, 10]} />
        <Physics>
          {nodesWithPositions.map(node => (
            <Node
              key={node.id}
              position={node.position}
              name={node.name}
              vulnerable={node.vulnerable}
              onClick={() => setSelectedNode(node)}
            />
          ))}
          {edges.map((edge, index) => (
            <Edge key={index} start={edge.start} end={edge.end} />
          ))}
        </Physics>
        <OrbitControls enableDamping dampingFactor={0.05} enableZoom enablePan />
      </Canvas>
      {selectedNode && (
        <div className="absolute bottom-4 left-4 glass p-4">
          <h3>{selectedNode.name}</h3>
          <p>Vulnerable: {selectedNode.vulnerable ? 'Yes' : 'No'}</p>
        </div>
      )}
    </div>
  );
}