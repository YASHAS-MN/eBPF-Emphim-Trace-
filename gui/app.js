/**
 * EPHIMTRACE // Standalone Zero-Dependency 3D Forensic Provenance Engine
 * Renders hardware-accelerated 3D polyhedral entities, perspective depth grids,
 * animated causal particles, and chronological forensic replay without external libraries.
 */

(function () {
  "use strict";

  // =========================================================================
  // 1. EMBEDDED FALLBACK COMPOSITE KILL-CHAIN ARTIFACT (Matches M7 Schema 1:1)
  // =========================================================================
  const FALLBACK_DAG = {
    version: "1.0",
    node_count: 5,
    edge_count: 6,
    nodes: [
      {
        id: "proc_25310_700000000000",
        type: "NODE_PROCESS",
        pid: 25310,
        ppid: 1940,
        comm: "dropper_parent",
        start_time_ns: 700000000000,
        exit_code: 0,
        is_alive: false,
      },
      {
        id: "proc_25313_700000000500",
        type: "NODE_PROCESS",
        pid: 25313,
        ppid: 25310,
        comm: "c2_beacon_exec",
        start_time_ns: 700000000500,
        exit_code: 0,
        is_alive: true,
      },
      {
        id: "memfd_778899",
        type: "NODE_MEMFD",
        object_token: 778899,
        creator_pid: 25313,
        creator_start_time: 700000000500,
        name: "c2_beacon",
        inode_no: 445566,
        dev_id: 66,
        is_destroyed: false,
      },
      {
        id: "fs_2049_889900",
        type: "NODE_FS_OBJECT",
        inode_no: 889900,
        dev_id: 2049,
        mnt_ns_id: 4026531840,
        path: "/tmp/ephim_c2_artifact.dat",
        is_unlinked: true,
      },
      {
        id: "net_2_127.0.0.1_8443",
        type: "NODE_NET_ENDPOINT",
        family: 2,
        ip_str: "127.0.0.1",
        port: 8443,
      },
    ],
    edges: [
      {
        src: "proc_25310_700000000000",
        dst: "proc_25313_700000000500",
        timestamp_ns: 700000001000,
        type: "EDGE_FORK",
      },
      {
        src: "proc_25313_700000000500",
        dst: "memfd_778899",
        timestamp_ns: 700000002000,
        type: "EDGE_MEMFD_CREATE",
        fd: 3,
      },
      {
        src: "proc_25313_700000000500",
        dst: "memfd_778899",
        timestamp_ns: 700000003000,
        type: "EDGE_MEMFD_WRITE",
        offset: 0,
        bytes: 26936,
      },
      {
        src: "proc_25313_700000000500",
        dst: "memfd_778899",
        timestamp_ns: 700000004000,
        type: "EDGE_MEMFD_EXEC_SUCCESS",
        binary_comm: "c2_beacon_exec",
      },
      {
        src: "proc_25313_700000000500",
        dst: "fs_2049_889900",
        timestamp_ns: 700000005000,
        type: "EDGE_UNLINK",
        path: "/tmp/ephim_c2_artifact.dat",
        status: "SUCCESS",
      },
      {
        src: "proc_25313_700000000500",
        dst: "net_2_127.0.0.1_8443",
        timestamp_ns: 700000006000,
        type: "EDGE_CONNECT",
        fd: 4,
        result: -111,
      },
    ],
  };

  const FALLBACK_TIMELINE_MD = `# EphimTrace Forensic Timeline Report

- **Target PID Filter**: 0
- **Target Token Filter**: 0
- **Correlated Nodes**: 5
- **Chronological Events**: 6

## Chronological Event Log

- \`[700000001000 ns]\` \`[FORK]\` Process 25310 (dropper_parent) -> fork() -> Child Process 25313
- \`[700000002000 ns]\` \`[MEMFD_CREATE]\` Process 25313 (c2_beacon_exec) -> memfd_create() -> Memfd 'c2_beacon' (Token: 778899, FD: 3)
- \`[700000003000 ns]\` \`[MEMFD_WRITE]\` Process 25313 (c2_beacon_exec) -> write() -> Memfd 'c2_beacon' (Token: 778899, Offset: 0, Bytes: 26936)
- \`[700000004000 ns]\` \`[MEMFD_EXEC_SUCCESS]\` Process 25313 (c2_beacon_exec) -> exec_success() -> Memfd 'c2_beacon' (Token: 778899, Binary: c2_beacon_exec)
- \`[700000005000 ns]\` \`[UNLINK]\` Process 25313 (c2_beacon_exec) -> unlink() -> FS Object '/tmp/ephim_c2_artifact.dat' (Status: SUCCESS)
- \`[700000006000 ns]\` \`[CONNECT]\` Process 25313 (c2_beacon_exec) -> connect() -> Net '127.0.0.1:8443' (FD: 4, Result: -111)
`;

  // =========================================================================
  // 2. COLOR & VISUAL ENCODING PALETTE
  // =========================================================================
  const NODE_PALETTE = {
    NODE_PROCESS: {
      color: "#00e5ff",
      glow: "rgba(0, 229, 255, 0.45)",
      shape: "CUBE",
    },
    NODE_MEMFD: {
      color: "#ffb300",
      glow: "rgba(255, 179, 0, 0.45)",
      shape: "OCTA",
    },
    NODE_FS_OBJECT: {
      color: "#00e676",
      glow: "rgba(0, 230, 118, 0.45)",
      shape: "CYL",
    },
    NODE_NET_ENDPOINT: {
      color: "#d500f9",
      glow: "rgba(213, 0, 249, 0.45)",
      shape: "DIA",
    },
  };

  const EDGE_PALETTE = {
    EDGE_FORK: "#00e5ff",
    EDGE_MEMFD_CREATE: "#ffb300",
    EDGE_FD_INSTALLED: "#ffd54f",
    EDGE_FD_CLOSED: "#90a4ae",
    EDGE_MEMFD_WRITE: "#ff6d00",
    EDGE_MEMFD_EXEC_ATTEMPT: "#ff4081",
    EDGE_MEMFD_EXEC_SUCCESS: "#ff1744",
    EDGE_UNLINK: "#00e676",
    EDGE_CONNECT: "#d500f9",
  };

  // =========================================================================
  // 3. ENGINE STATE
  // =========================================================================
  const canvas = document.getElementById("viewport3d");
  const ctx = canvas.getContext("2d");

  let rawData = null;
  let nodes = [];
  let edges = [];
  let sortedEdges = [];
  let nodeMap = new Map();

  let minTs = 0;
  let maxTs = 0;
  let currentStep = 0;
  let isPlaying = false;
  let playTimer = null;

  // Layout mode: "FORCE" | "STRATA"
  let layoutMode = "FORCE";

  // 3D Camera State
  const cam = {
    yaw: -0.45,
    pitch: 0.32,
    distance: 620,
    targetX: 0,
    targetY: 0,
    targetZ: 0,
    goalX: 0,
    goalY: 0,
    goalZ: 0,
    goalDist: 620,
    autoOrbit: true,
  };

  // Interaction State
  let selectedItem = null; // { kind: 'node'|'edge', data: ... }
  let hoveredNode = null;
  let isolatedSet = null; // Set of node IDs or null
  let dragMode = null; // 'orbit' | 'pan' | 'node'
  let draggedNode = null;
  let lastMouse = { x: 0, y: 0 };
  let mouseDownPos = { x: 0, y: 0 };

  // Filter State
  let searchQuery = "";
  const activeNodeTypes = new Set(Object.keys(NODE_PALETTE));
  const activeEdgeTypes = new Set(Object.keys(EDGE_PALETTE));

  // Ambient 3D Starfield for depth reference
  const stars = Array.from({ length: 140 }, () => ({
    x: (Math.random() - 0.5) * 1600,
    y: (Math.random() - 0.5) * 1000,
    z: (Math.random() - 0.5) * 1600,
    size: Math.random() * 1.6 + 0.5,
  }));

  // =========================================================================
  // 4. INITIALIZATION & DATA INGESTION
  // =========================================================================
  function resizeCanvas() {
    const dpr = window.devicePixelRatio || 1;
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();

  function loadGraphData(json, sourceName) {
    rawData = json;
    nodes = [];
    edges = [];
    nodeMap.clear();
    isolatedSet = null;
    selectedItem = null;

    const rawNodes = Array.isArray(json.nodes) ? json.nodes : [];
    const rawEdges = Array.isArray(json.edges) ? json.edges : [];

    // Place nodes initially in a 3D spherical distribution
    const count = Math.max(rawNodes.length, 1);
    rawNodes.forEach((n, idx) => {
      const phi = Math.acos(1 - (2 * (idx + 0.5)) / count);
      const theta = Math.PI * (1 + Math.sqrt(5)) * idx;
      const radius = 170;

      const nodeObj = {
        ...n,
        x: radius * Math.cos(theta) * Math.sin(phi),
        y: radius * Math.cos(phi),
        z: radius * Math.sin(theta) * Math.sin(phi),
        vx: 0,
        vy: 0,
        vz: 0,
        proj: { x: 0, y: 0, z: 1, scale: 1, visible: false },
        firstTs: Infinity,
      };
      nodes.push(nodeObj);
      nodeMap.set(n.id, nodeObj);
    });

    // Group parallel edges between same src/dst so they curve cleanly in 3D
    const pairCounts = new Map();
    rawEdges.forEach((e, idx) => {
      const s = nodeMap.get(e.src);
      const d = nodeMap.get(e.dst);
      if (!s || !d) return;

      const pairKey = e.src < e.dst ? `${e.src}|${e.dst}` : `${e.dst}|${e.src}`;
      const k = pairCounts.get(pairKey) || 0;
      pairCounts.set(pairKey, k + 1);

      const ts = Number(e.timestamp_ns || 0);
      if (ts > 0) {
        if (ts < s.firstTs) s.firstTs = ts;
        if (ts < d.firstTs) d.firstTs = ts;
      }

      edges.push({
        ...e,
        id: `edge_${idx}_${ts}`,
        sourceNode: s,
        targetNode: d,
        curveIndex: k,
        timestamp_ns: ts,
      });
    });

    sortedEdges = [...edges].sort((a, b) => a.timestamp_ns - b.timestamp_ns);

    if (sortedEdges.length > 0) {
      minTs = sortedEdges[0].timestamp_ns;
      maxTs = sortedEdges[sortedEdges.length - 1].timestamp_ns;
    } else {
      minTs = 0;
      maxTs = 0;
    }

    nodes.forEach((n) => {
      if (!Number.isFinite(n.firstTs)) {
        n.firstTs = n.start_time_ns || n.creator_start_time || minTs;
      }
    });

    // Update Top Metrics
    document.getElementById("stat-nodes").textContent = nodes.length;
    document.getElementById("stat-edges").textContent = edges.length;
    document.getElementById("stat-span").textContent = Math.max(
      0,
      maxTs - minTs,
    ).toLocaleString();
    document.getElementById("status-sub").textContent =
      `SOURCE: ${sourceName.toUpperCase()}`;

    // Configure Timeline Scrubber
    const slider = document.getElementById("timeline-slider");
    slider.max = sortedEdges.length;
    slider.value = sortedEdges.length;
    currentStep = sortedEdges.length;

    updateScrubberUI();
    renderEventLog();

    if (nodes.length > 0) {
      inspectNode(nodes[0]);
    }
  }

  // =========================================================================
  // 5. 3D PHYSICS & CHRONOLOGICAL STRATA SOLVER
  // =========================================================================
  function stepPhysics() {
    const N = nodes.length;
    if (N === 0) return;

    if (layoutMode === "STRATA") {
      // Mode B: Y-axis = Architectural Domain, Z-axis = Chronological Time
      const span = Math.max(1, maxTs - minTs);
      nodes.forEach((n, idx) => {
        if (n === draggedNode) return;
        let targetY = 0;
        if (n.type === "NODE_PROCESS")
          targetY = -130; // Top plane in screen space
        else if (n.type === "NODE_MEMFD")
          targetY = 0; // Middle plane
        else targetY = 130; // Bottom plane (FS & Network)

        const normT = (n.firstTs - minTs) / span;
        const targetZ = (normT - 0.5) * 380;
        const targetX = ((idx % 5) - 2) * 110;

        n.x += (targetX - n.x) * 0.08;
        n.y += (targetY - n.y) * 0.08;
        n.z += (targetZ - n.z) * 0.08;
      });
      return;
    }

    // Mode A: 3D Force-Directed Physics
    const repulsion = 24000;
    const springLen = 165;
    const springK = 0.035;

    for (let i = 0; i < N; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < N; j++) {
        const b = nodes[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let dz = a.z - b.z;
        let distSq = dx * dx + dy * dy + dz * dz + 40;
        let dist = Math.sqrt(distSq);
        let force = repulsion / distSq;

        let fx = (dx / dist) * force;
        let fy = (dy / dist) * force;
        let fz = (dz / dist) * force;

        a.vx += fx;
        a.vy += fy;
        a.vz += fz;
        b.vx -= fx;
        b.vy -= fy;
        b.vz -= fz;
      }
    }

    edges.forEach((e) => {
      const s = e.sourceNode;
      const t = e.targetNode;
      let dx = t.x - s.x;
      let dy = t.y - s.y;
      let dz = t.z - s.z;
      let dist = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
      let displacement = dist - springLen;
      let force = displacement * springK;

      let fx = (dx / dist) * force;
      let fy = (dy / dist) * force;
      let fz = (dz / dist) * force;

      s.vx += fx;
      s.vy += fy;
      s.vz += fz;
      t.vx -= fx;
      t.vy -= fy;
      t.vz -= fz;
    });

    nodes.forEach((n) => {
      if (n === draggedNode) return;
      // Gentle centering gravity
      n.vx -= n.x * 0.012;
      n.vy -= n.y * 0.012;
      n.vz -= n.z * 0.012;

      n.vx *= 0.78;
      n.vy *= 0.78;
      n.vz *= 0.78;

      n.x += n.vx;
      n.y += n.vy;
      n.z += n.vz;
    });
  }

  // =========================================================================
  // 6. 3D PROJECTION & GEOMETRY PRIMITIVES
  // =========================================================================
  function project3D(x, y, z, width, height) {
    // Translate relative to camera target
    const rx = x - cam.targetX;
    const ry = y - cam.targetY;
    const rz = z - cam.targetZ;

    // Rotate around Y (yaw)
    const cosY = Math.cos(cam.yaw);
    const sinY = Math.sin(cam.yaw);
    const x1 = rx * cosY - rz * sinY;
    const z1 = rz * cosY + rx * sinY;

    // Rotate around X (pitch)
    const cosP = Math.cos(cam.pitch);
    const sinP = Math.sin(cam.pitch);
    const y2 = ry * cosP - z1 * sinP;
    const z2 = z1 * cosP + ry * sinP + cam.distance;

    if (z2 < 40) {
      return { x: 0, y: 0, z: z2, scale: 0, visible: false };
    }

    const fov = 680;
    const scale = fov / z2;
    return {
      x: width * 0.5 + x1 * scale,
      y: height * 0.45 + y2 * scale,
      z: z2,
      scale: scale,
      visible: true,
    };
  }

  function draw3DGrid(width, height) {
    ctx.strokeStyle = "rgba(0, 229, 255, 0.07)";
    ctx.lineWidth = 1;
    const gridY = 185;
    const extent = 400;
    const step = 80;

    for (let i = -extent; i <= extent; i += step) {
      const p1 = project3D(i, gridY, -extent, width, height);
      const p2 = project3D(i, gridY, extent, width, height);
      if (p1.visible && p2.visible) {
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      }

      const q1 = project3D(-extent, gridY, i, width, height);
      const q2 = project3D(extent, gridY, i, width, height);
      if (q1.visible && q2.visible) {
        ctx.beginPath();
        ctx.moveTo(q1.x, q1.y);
        ctx.lineTo(q2.x, q2.y);
        ctx.stroke();
      }
    }
  }

  // Renders 3D Polyhedra (Cube, Octahedron, Cylinder, Diamond) rotated in 3D space
  function drawPolyhedron(
    node,
    width,
    height,
    alpha,
    isSelected,
    isHovered,
    timeSec,
  ) {
    const pal = NODE_PALETTE[node.type] || NODE_PALETTE.NODE_PROCESS;
    const p = node.proj;
    if (!p.visible) return;

    const r = 20; // 3D world radius of polyhedron
    const spin = timeSec * 0.7 + (node.pid || node.object_token || 1);

    ctx.save();
    ctx.globalAlpha = alpha;

    // Outer Halo Glow
    const screenRadius = Math.max(8, r * p.scale);
    const grad = ctx.createRadialGradient(
      p.x,
      p.y,
      screenRadius * 0.2,
      p.x,
      p.y,
      screenRadius * 2.3,
    );
    grad.addColorStop(0, pal.glow);
    grad.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.arc(p.x, p.y, screenRadius * 2.3, 0, Math.PI * 2);
    ctx.fill();

    // Generate 3D vertices & edges based on entity type
    let verts = [];
    let wireEdges = [];

    if (node.type === "NODE_PROCESS") {
      // 3D Cube
      const s = r * 0.85;
      verts = [
        [-s, -s, -s],
        [s, -s, -s],
        [s, s, -s],
        [-s, s, -s],
        [-s, -s, s],
        [s, -s, s],
        [s, s, s],
        [-s, s, s],
      ];
      wireEdges = [
        [0, 1],
        [1, 2],
        [2, 3],
        [3, 0],
        [4, 5],
        [5, 6],
        [6, 7],
        [7, 4],
        [0, 4],
        [1, 5],
        [2, 6],
        [3, 7],
      ];
    } else if (node.type === "NODE_MEMFD") {
      // 3D Octahedron
      const s = r * 1.15;
      verts = [
        [0, -s, 0],
        [0, s, 0],
        [-s, 0, 0],
        [s, 0, 0],
        [0, 0, -s],
        [0, 0, s],
      ];
      wireEdges = [
        [0, 2],
        [0, 3],
        [0, 4],
        [0, 5],
        [1, 2],
        [1, 3],
        [1, 4],
        [1, 5],
        [2, 4],
        [4, 3],
        [3, 5],
        [5, 2],
      ];
    } else if (node.type === "NODE_FS_OBJECT") {
      // 3D Hexagonal Prism / Cylinder
      const sides = 6;
      const h = r * 0.85;
      for (let i = 0; i < sides; i++) {
        const a = (i / sides) * Math.PI * 2;
        verts.push([Math.cos(a) * r, -h, Math.sin(a) * r]);
      }
      for (let i = 0; i < sides; i++) {
        const a = (i / sides) * Math.PI * 2;
        verts.push([Math.cos(a) * r, h, Math.sin(a) * r]);
      }
      for (let i = 0; i < sides; i++) {
        const nxt = (i + 1) % sides;
        wireEdges.push([i, nxt]);
        wireEdges.push([i + sides, nxt + sides]);
        wireEdges.push([i, i + sides]);
      }
    } else {
      // NODE_NET_ENDPOINT: 3D Bipyramid / Diamond Torus
      const s = r * 1.15;
      verts = [
        [0, -s * 0.7, 0],
        [0, s * 0.7, 0],
        [-s, 0, -s * 0.5],
        [s, 0, -s * 0.5],
        [s, 0, s * 0.5],
        [-s, 0, s * 0.5],
      ];
      wireEdges = [
        [0, 2],
        [0, 3],
        [0, 4],
        [0, 5],
        [1, 2],
        [1, 3],
        [1, 4],
        [1, 5],
        [2, 3],
        [3, 4],
        [4, 5],
        [5, 2],
      ];
    }

    // Rotate local vertices slightly for 3D kinetic feel and project to 2D
    const cosS = Math.cos(spin * 0.35);
    const sinS = Math.sin(spin * 0.35);
    const projVerts = verts.map(([vx, vy, vz]) => {
      const rx = vx * cosS - vz * sinS;
      const rz = vz * cosS + vx * sinS;
      return project3D(node.x + rx, node.y + vy, node.z + rz, width, height);
    });

    // Core Solid Nucleus
    ctx.fillStyle = pal.color;
    ctx.beginPath();
    ctx.arc(p.x, p.y, screenRadius * 0.32, 0, Math.PI * 2);
    ctx.fill();

    // Draw 3D Polyhedron Wireframe
    ctx.strokeStyle = isSelected || isHovered ? "#ffffff" : pal.color;
    ctx.lineWidth = isSelected ? 2.2 : 1.35;

    const isRetired =
      (node.type === "NODE_PROCESS" && node.is_alive === false) ||
      (node.type === "NODE_MEMFD" && node.is_destroyed === true) ||
      (node.type === "NODE_FS_OBJECT" && node.is_unlinked === true);

    if (isRetired) {
      ctx.setLineDash([3, 3]);
    }

    ctx.beginPath();
    wireEdges.forEach(([i, j]) => {
      const a = projVerts[i];
      const b = projVerts[j];
      if (a.visible && b.visible) {
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
      }
    });
    ctx.stroke();
    ctx.setLineDash([]);

    // Selection / Alert Ring
    if (
      isSelected ||
      isHovered ||
      (node.type === "NODE_FS_OBJECT" && node.is_unlinked)
    ) {
      ctx.strokeStyle = isSelected
        ? "#ffffff"
        : node.is_unlinked
          ? "#ff1744"
          : pal.color;
      ctx.lineWidth = isSelected ? 2 : 1.2;
      ctx.beginPath();
      ctx.arc(p.x, p.y, screenRadius * 1.35, 0, Math.PI * 2);
      ctx.stroke();
    }

    // Crisp HUD Label Below 3D Node
    const title = formatNodePrimaryLabel(node);
    const badge = formatNodeStatusBadge(node);

    ctx.font = "bold 11px 'JetBrains Mono', monospace";
    const textW = ctx.measureText(title).width;
    const labelY = p.y + screenRadius * 1.45 + 10;

    ctx.fillStyle = "rgba(3, 10, 16, 0.82)";
    ctx.fillRect(p.x - textW / 2 - 5, labelY - 10, textW + 10, badge ? 26 : 15);
    ctx.strokeStyle = "rgba(0, 229, 255, 0.25)";
    ctx.lineWidth = 1;
    ctx.strokeRect(
      p.x - textW / 2 - 5,
      labelY - 10,
      textW + 10,
      badge ? 26 : 15,
    );

    ctx.fillStyle = "#e2f8ff";
    ctx.textAlign = "center";
    ctx.fillText(title, p.x, labelY);

    if (badge) {
      ctx.font = "9px 'JetBrains Mono', monospace";
      ctx.fillStyle = badge.color;
      ctx.fillText(badge.text, p.x, labelY + 11);
    }

    ctx.restore();
  }

  // =========================================================================
  // 7. MAIN RENDER LOOP
  // =========================================================================
  function isNodePassingFilter(node) {
    if (!activeNodeTypes.has(node.type)) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const hay = [
      node.id,
      node.comm,
      node.name,
      node.path,
      node.ip_str,
      node.pid,
      node.object_token,
      node.inode_no,
    ]
      .filter((v) => v !== undefined)
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  }

  function renderFrame(nowMs) {
    const timeSec = nowMs * 0.001;
    const width = window.innerWidth;
    const height = window.innerHeight;

    ctx.clearRect(0, 0, width, height);

    // Smooth camera interpolation toward target
    cam.targetX += (cam.goalX - cam.targetX) * 0.1;
    cam.targetY += (cam.goalY - cam.targetY) * 0.1;
    cam.targetZ += (cam.goalZ - cam.targetZ) * 0.1;
    cam.distance += (cam.goalDist - cam.distance) * 0.1;

    if (cam.autoOrbit && !dragMode) {
      cam.yaw += 0.0018;
    }

    stepPhysics();

    // 1. Render Ambient 3D Starfield
    ctx.fillStyle = "rgba(0, 229, 255, 0.32)";
    stars.forEach((s) => {
      const sp = project3D(s.x, s.y, s.z, width, height);
      if (sp.visible) {
        ctx.fillRect(sp.x, sp.y, s.size, s.size);
      }
    });

    // 2. Render 3D Floor Reference Grid
    draw3DGrid(width, height);

    // 3. Project all 3D Nodes
    nodes.forEach((n) => {
      n.proj = project3D(n.x, n.y, n.z, width, height);
    });

    // Determine timeline cutoff timestamp
    const activeSlice = sortedEdges.slice(0, currentStep);
    const activeEdgeIds = new Set(activeSlice.map((e) => e.id));
    const cutoffTs =
      currentStep === 0
        ? -1
        : currentStep >= sortedEdges.length
          ? Infinity
          : sortedEdges[currentStep - 1].timestamp_ns;

    // 4. Render Directed 3D Edges & Flowing Causal Particles
    edges.forEach((e) => {
      if (!activeEdgeTypes.has(e.type)) return;
      if (!activeEdgeIds.has(e.id)) return;

      const s = e.sourceNode;
      const d = e.targetNode;
      if (!s.proj.visible || !d.proj.visible) return;

      const filterDim =
        !isNodePassingFilter(s) ||
        !isNodePassingFilter(d) ||
        (isolatedSet && (!isolatedSet.has(s.id) || !isolatedSet.has(d.id)));

      const alpha = filterDim ? 0.12 : 0.88;
      const color = EDGE_PALETTE[e.type] || "#00e5ff";

      // 3D Midpoint with offset for multi-edges between the same entity pair
      const offsetMag = e.curveIndex * 24;
      const mx = (s.x + d.x) * 0.5 + offsetMag;
      const my = (s.y + d.y) * 0.5 - offsetMag * 0.7;
      const mz = (s.z + d.z) * 0.5 + offsetMag;
      const mp = project3D(mx, my, mz, width, height);

      ctx.save();
      ctx.globalAlpha = alpha;
      ctx.strokeStyle = color;
      ctx.lineWidth = selectedItem && selectedItem.data === e ? 2.8 : 1.5;

      ctx.beginPath();
      ctx.moveTo(s.proj.x, s.proj.y);
      ctx.quadraticCurveTo(mp.x, mp.y, d.proj.x, d.proj.y);
      ctx.stroke();

      // Animated Glowing Particle along Quadratic Bezier
      if (!filterDim) {
        const t = (timeSec * 0.65 + e.curveIndex * 0.23) % 1;
        const omt = 1 - t;
        const px = omt * omt * s.proj.x + 2 * omt * t * mp.x + t * t * d.proj.x;
        const py = omt * omt * s.proj.y + 2 * omt * t * mp.y + t * t * d.proj.y;

        ctx.fillStyle = "#ffffff";
        ctx.shadowColor = color;
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(px, py, 3.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Edge type micro-tag near curve midpoint
        if (e.curveIndex === 0 || (selectedItem && selectedItem.data === e)) {
          const shortType = e.type.replace("EDGE_", "");
          ctx.font = "9px 'JetBrains Mono', monospace";
          ctx.fillStyle = color;
          ctx.textAlign = "center";
          ctx.fillText(shortType, mp.x, mp.y - 4);
        }
      }

      ctx.restore();
    });

    // 5. Depth-Sort Nodes (Painter's Algorithm back-to-front)
    const depthSortedNodes = [...nodes].sort((a, b) => b.proj.z - a.proj.z);

    depthSortedNodes.forEach((n) => {
      const visibleInTimeline =
        currentStep >= sortedEdges.length || n.firstTs <= cutoffTs;
      const passFilter = isNodePassingFilter(n);
      const passIsolate = !isolatedSet || isolatedSet.has(n.id);

      let alpha = 1.0;
      if (!visibleInTimeline) alpha = 0.14;
      else if (!passFilter || !passIsolate) alpha = 0.16;

      const isSel =
        selectedItem &&
        selectedItem.kind === "node" &&
        selectedItem.data.id === n.id;
      const isHov = hoveredNode && hoveredNode.id === n.id;

      drawPolyhedron(n, width, height, alpha, isSel, isHov, timeSec);
    });

    requestAnimationFrame(renderFrame);
  }

  // =========================================================================
  // 8. FORMATTING & EVIDENCE INSPECTOR HELPERS
  // =========================================================================
  function formatNodePrimaryLabel(n) {
    if (n.type === "NODE_PROCESS") return `${n.comm || "proc"} (PID ${n.pid})`;
    if (n.type === "NODE_MEMFD") return `memfd:${n.name || n.object_token}`;
    if (n.type === "NODE_FS_OBJECT") {
      const parts = (n.path || "").split("/");
      return parts[parts.length - 1] || n.id;
    }
    if (n.type === "NODE_NET_ENDPOINT") {
      if (n.family === 1 || n.ip_str === "<unsupported>")
        return `AF_UNIX:${n.port || 0}`;
      return `${n.ip_str}:${n.port}`;
    }
    return n.id;
  }

  function formatNodeStatusBadge(n) {
    if (n.type === "NODE_PROCESS") {
      return n.is_alive
        ? { text: "[ALIVE]", color: "#00e676" }
        : { text: `[DEAD · EXIT ${n.exit_code}]`, color: "#ff5252" };
    }
    if (n.type === "NODE_MEMFD") {
      return n.is_destroyed
        ? { text: `[TOKEN ${n.object_token} · DESTROYED]`, color: "#ffab40" }
        : { text: `[TOKEN ${n.object_token} · ACTIVE]`, color: "#ffd740" };
    }
    if (n.type === "NODE_FS_OBJECT") {
      return n.is_unlinked
        ? { text: "[UNLINKED]", color: "#ff1744" }
        : { text: "[ON-DISK]", color: "#00e676" };
    }
    if (n.type === "NODE_NET_ENDPOINT") {
      const fam =
        n.family === 2 ? "AF_INET" : n.family === 10 ? "AF_INET6" : "AF_UNIX";
      return { text: `[${fam}]`, color: "#e040fb" };
    }
    return null;
  }

  function inspectNode(node) {
    selectedItem = { kind: "node", data: node };
    const box = document.getElementById("inspector-content");

    const relatedEdges = sortedEdges.filter(
      (e) => e.src === node.id || e.dst === node.id,
    );
    const rows = [
      ["Entity ID", node.id],
      ["Entity Class", node.type],
      [
        "Evidence Basis",
        '<span class="badge badge-derived">CORRELATED IDENTITY</span>',
      ],
    ];

    if (node.type === "NODE_PROCESS") {
      rows.push(["PID / PPID", `${node.pid} / ${node.ppid}`]);
      rows.push(["Executable (comm)", node.comm]);
      rows.push(["Start Boottime", `${node.start_time_ns} ns`]);
      rows.push([
        "Lifecycle State",
        node.is_alive ? "ALIVE" : `EXITED (${node.exit_code})`,
      ]);
    } else if (node.type === "NODE_MEMFD") {
      rows.push(["Object Token", node.object_token]);
      rows.push(["Memfd Name", node.name]);
      rows.push(["Creator PID", node.creator_pid]);
      rows.push(["Backing Inode / Dev", `${node.inode_no} / ${node.dev_id}`]);
      rows.push([
        "Backing Status",
        node.is_destroyed ? "DESTROYED (Evicted)" : "ACTIVE IN RAM",
      ]);
    } else if (node.type === "NODE_FS_OBJECT") {
      rows.push(["Resolved Path", node.path]);
      rows.push(["Inode / Dev ID", `${node.inode_no} / ${node.dev_id}`]);
      rows.push(["Mount Namespace", node.mnt_ns_id]);
      rows.push([
        "Directory Status",
        node.is_unlinked
          ? '<span class="badge badge-alert">UNLINKED</span>'
          : "ACTIVE",
      ]);
    } else if (node.type === "NODE_NET_ENDPOINT") {
      const fam =
        node.family === 2
          ? "AF_INET (2)"
          : node.family === 10
            ? "AF_INET6 (10)"
            : `AF_UNIX (${node.family})`;
      rows.push(["Address Family", fam]);
      rows.push([
        "Remote Address",
        node.ip_str === "<unsupported>" ? "Local Unix Socket" : node.ip_str,
      ]);
      rows.push(["Remote Port", node.port]);
    }

    rows.push(["Connected Events", `${relatedEdges.length} edges`]);

    box.innerHTML = rows
      .map(
        ([k, v]) =>
          `<div class="kv-row"><span class="kv-key">${k}</span><span class="kv-val">${v}</span></div>`,
      )
      .join("");
  }

  function inspectEdge(edge) {
    selectedItem = { kind: "edge", data: edge };
    const box = document.getElementById("inspector-content");
    const relOffset = edge.timestamp_ns - minTs;

    const rows = [
      ["Signal Type", edge.type],
      [
        "Evidence Category",
        '<span class="badge badge-observed">DIRECT BPF EVENT</span>',
      ],
      ["Source Entity", edge.src],
      ["Target Entity", edge.dst],
      ["Kernel Timestamp", `${edge.timestamp_ns} ns`],
      ["Relative Offset", `+${relOffset.toLocaleString()} ns`],
    ];

    if (edge.fd !== undefined) rows.push(["File Descriptor (FD)", edge.fd]);
    if (edge.install_type !== undefined)
      rows.push(["Install Mechanism", edge.install_type]);
    if (edge.duration_ns !== undefined)
      rows.push(["FD Lifetime", `${edge.duration_ns.toLocaleString()} ns`]);
    if (edge.offset !== undefined) rows.push(["Write Offset", edge.offset]);
    if (edge.bytes !== undefined)
      rows.push(["Bytes Written", `${edge.bytes.toLocaleString()} B`]);
    if (edge.filename !== undefined)
      rows.push(["Target Filename", edge.filename]);
    if (edge.binary_comm !== undefined)
      rows.push(["Committed Image", edge.binary_comm]);
    if (edge.path !== undefined) rows.push(["Unlinked Path", edge.path]);
    if (edge.status !== undefined) rows.push(["VFS Status", edge.status]);
    if (edge.result !== undefined) rows.push(["Connect Result", edge.result]);

    box.innerHTML = rows
      .map(
        ([k, v]) =>
          `<div class="kv-row"><span class="kv-key">${k}</span><span class="kv-val">${v}</span></div>`,
      )
      .join("");
  }

  // =========================================================================
  // 9. TIMELINE SCRUBBER & EVENT LOG
  // =========================================================================
  function updateScrubberUI() {
    const label = document.getElementById("scrubber-counter");
    label.textContent = `EVENT ${currentStep} / ${sortedEdges.length}`;
    document.getElementById("timeline-slider").value = currentStep;

    const items = document.querySelectorAll(".log-item");
    items.forEach((el, idx) => {
      el.classList.toggle("active-event", idx === currentStep - 1);
    });
  }

  function renderEventLog() {
    const list = document.getElementById("event-log-list");
    list.innerHTML = "";

    sortedEdges.forEach((e, idx) => {
      const div = document.createElement("div");
      div.className = "log-item";

      let meta = "";
      if (e.fd !== undefined) meta += `fd=${e.fd} `;
      if (e.install_type) meta += `type=${e.install_type} `;
      if (e.bytes !== undefined) meta += `bytes=${e.bytes} `;
      if (e.binary_comm) meta += `bin=${e.binary_comm} `;
      if (e.status) meta += `status=${e.status} `;
      if (e.result !== undefined) meta += `ret=${e.result}`;

      div.innerHTML = `
        <span class="log-ts">${e.timestamp_ns} ns</span>
        <span class="log-type">${e.type}</span>
        <span class="log-flow">${e.src} → ${e.dst}</span>
        <span class="log-meta">${meta}</span>
      `;

      div.addEventListener("click", () => {
        currentStep = idx + 1;
        updateScrubberUI();
        inspectEdge(e);
        if (e.targetNode) {
          cam.goalX = e.targetNode.x;
          cam.goalY = e.targetNode.y;
          cam.goalZ = e.targetNode.z;
          cam.autoOrbit = false;
        }
      });

      list.appendChild(div);
    });
  }

  // =========================================================================
  // 10. POINTER, CAMERA, & UI EVENT LISTENERS
  // =========================================================================
  function findNodeAtScreenPos(mx, my) {
    // Check front-to-back
    const frontToBack = [...nodes].sort((a, b) => a.proj.z - b.proj.z);
    for (const n of frontToBack) {
      if (!n.proj.visible) continue;
      const hitRadius = Math.max(14, 22 * n.proj.scale);
      const dx = mx - n.proj.x;
      const dy = my - n.proj.y;
      if (dx * dx + dy * dy <= hitRadius * hitRadius) {
        return n;
      }
    }
    return null;
  }

  canvas.addEventListener("contextmenu", (e) => e.preventDefault());

  canvas.addEventListener("mousedown", (e) => {
    lastMouse = { x: e.clientX, y: e.clientY };
    mouseDownPos = { x: e.clientX, y: e.clientY };
    cam.autoOrbit = false;

    if (e.button === 2 || e.shiftKey) {
      dragMode = "pan";
      return;
    }

    const hit = findNodeAtScreenPos(e.clientX, e.clientY);
    if (hit) {
      dragMode = "node";
      draggedNode = hit;
    } else {
      dragMode = "orbit";
    }
  });

  window.addEventListener("mousemove", (e) => {
    const dx = e.clientX - lastMouse.x;
    const dy = e.clientY - lastMouse.y;
    lastMouse = { x: e.clientX, y: e.clientY };

    if (!dragMode) {
      hoveredNode = findNodeAtScreenPos(e.clientX, e.clientY);
      canvas.style.cursor = hoveredNode ? "pointer" : "grab";
      return;
    }

    if (dragMode === "orbit") {
      cam.yaw += dx * 0.0065;
      cam.pitch = Math.max(-1.35, Math.min(1.35, cam.pitch + dy * 0.0065));
    } else if (dragMode === "pan") {
      cam.goalX -= dx * 0.7;
      cam.goalY -= dy * 0.7;
    } else if (dragMode === "node" && draggedNode) {
      const factor = 1 / Math.max(0.3, draggedNode.proj.scale);
      const cosY = Math.cos(-cam.yaw);
      const sinY = Math.sin(-cam.yaw);
      draggedNode.x += dx * factor * cosY;
      draggedNode.z += dx * factor * sinY;
      draggedNode.y += dy * factor;
    }
  });

  window.addEventListener("mouseup", (e) => {
    const moveDist = Math.hypot(
      e.clientX - mouseDownPos.x,
      e.clientY - mouseDownPos.y,
    );
    if (moveDist < 5) {
      const hit = findNodeAtScreenPos(e.clientX, e.clientY);
      if (hit) {
        inspectNode(hit);
        cam.goalX = hit.x;
        cam.goalY = hit.y;
        cam.goalZ = hit.z;
      }
    }
    dragMode = null;
    draggedNode = null;
  });

  canvas.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      cam.goalDist = Math.max(
        160,
        Math.min(1800, cam.goalDist + e.deltaY * 0.55),
      );
    },
    { passive: false },
  );

  // Top Bar Controls
  document.getElementById("btn-layout").addEventListener("click", (e) => {
    layoutMode = layoutMode === "FORCE" ? "STRATA" : "FORCE";
    e.target.textContent =
      layoutMode === "FORCE" ? "MODE: 3D FORCE ORBIT" : "MODE: 3D TIME STRATA";
  });

  document.getElementById("btn-reset-cam").addEventListener("click", () => {
    cam.goalX = 0;
    cam.goalY = 0;
    cam.goalZ = 0;
    cam.goalDist = 620;
    cam.yaw = -0.45;
    cam.pitch = 0.32;
    cam.autoOrbit = true;
  });

  document.getElementById("btn-reload").addEventListener("click", async () => {
    try {
      const res = await fetch("../ephimtrace_dag.json", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      loadGraphData(data, "ephimtrace_dag.json (HTTP)");
    } catch (_) {
      loadGraphData(FALLBACK_DAG, "EMBEDDED M7 COMPOSITE DAG");
    }
  });

  // File Inputs & Drag-Drop
  function handleFileRead(file) {
    const reader = new FileReader();
    reader.onload = () => {
      if (file.name.endsWith(".md") || file.name.endsWith(".txt")) {
        document.getElementById("markdown-viewer").textContent = reader.result;
        document.getElementById("tab-markdown").click();
      } else {
        try {
          const parsed = JSON.parse(reader.result);
          loadGraphData(parsed, file.name);
        } catch (err) {
          alert("Invalid JSON file: " + err.message);
        }
      }
    };
    reader.readAsText(file);
  }

  document.getElementById("file-json-input").addEventListener("change", (e) => {
    if (e.target.files[0]) handleFileRead(e.target.files[0]);
  });

  document.getElementById("file-md-input").addEventListener("change", (e) => {
    if (e.target.files[0]) handleFileRead(e.target.files[0]);
  });

  window.addEventListener("dragover", (e) => {
    e.preventDefault();
    document.getElementById("drop-overlay").classList.remove("hidden");
  });

  window.addEventListener("dragleave", (e) => {
    if (e.target === document.getElementById("drop-overlay")) {
      document.getElementById("drop-overlay").classList.add("hidden");
    }
  });

  window.addEventListener("drop", (e) => {
    e.preventDefault();
    document.getElementById("drop-overlay").classList.add("hidden");
    if (e.dataTransfer.files[0]) handleFileRead(e.dataTransfer.files[0]);
  });

  // Filter & Blast Radius Isolation
  document.getElementById("search-input").addEventListener("input", (e) => {
    searchQuery = e.target.value.trim();
  });

  document.querySelectorAll("[data-node-type]").forEach((cb) => {
    cb.addEventListener("change", (e) => {
      const t = e.target.getAttribute("data-node-type");
      if (e.target.checked) activeNodeTypes.add(t);
      else activeNodeTypes.delete(t);
    });
  });

  document.querySelectorAll("[data-edge-type]").forEach((cb) => {
    cb.addEventListener("change", (e) => {
      const t = e.target.getAttribute("data-edge-type");
      if (e.target.checked) activeEdgeTypes.add(t);
      else activeEdgeTypes.delete(t);
    });
  });

  document.getElementById("btn-isolate").addEventListener("click", () => {
    if (!selectedItem || selectedItem.kind !== "node") return;
    const seedId = selectedItem.data.id;
    const visited = new Set([seedId]);
    const queue = [seedId];

    while (queue.length > 0) {
      const curr = queue.shift();
      edges.forEach((e) => {
        if (e.src === curr && !visited.has(e.dst)) {
          visited.add(e.dst);
          queue.push(e.dst);
        }
        if (e.dst === curr && !visited.has(e.src)) {
          visited.add(e.src);
          queue.push(e.src);
        }
      });
    }
    isolatedSet = visited;
  });

  document.getElementById("btn-clear-isolate").addEventListener("click", () => {
    isolatedSet = null;
  });

  document
    .getElementById("btn-close-inspector")
    .addEventListener("click", () => {
      selectedItem = null;
      document.getElementById("inspector-content").innerHTML =
        '<div class="empty-hint">Click any 3D entity or chronological event below to inspect raw kernel provenance telemetry.</div>';
    });

  // Timeline Scrubber Controls
  document.getElementById("timeline-slider").addEventListener("input", (e) => {
    currentStep = Number(e.target.value);
    updateScrubberUI();
  });

  document.getElementById("btn-step-back").addEventListener("click", () => {
    currentStep = Math.max(0, currentStep - 1);
    updateScrubberUI();
  });

  document.getElementById("btn-step-fwd").addEventListener("click", () => {
    currentStep = Math.min(sortedEdges.length, currentStep + 1);
    updateScrubberUI();
  });

  document.getElementById("btn-play").addEventListener("click", (e) => {
    if (isPlaying) {
      clearInterval(playTimer);
      isPlaying = false;
      e.target.textContent = "▶ PLAY";
      return;
    }
    if (currentStep >= sortedEdges.length) currentStep = 0;
    isPlaying = true;
    e.target.textContent = "⏸ PAUSE";
    playTimer = setInterval(() => {
      if (currentStep < sortedEdges.length) {
        currentStep++;
        updateScrubberUI();
      } else {
        clearInterval(playTimer);
        isPlaying = false;
        e.target.textContent = "▶ PLAY";
      }
    }, 650);
  });

  // Bottom Tabs
  document.getElementById("tab-events").addEventListener("click", () => {
    document.getElementById("tab-events").classList.add("active");
    document.getElementById("tab-markdown").classList.remove("active");
    document.getElementById("event-log-list").classList.remove("hidden");
    document.getElementById("markdown-viewer").classList.add("hidden");
  });

  document.getElementById("tab-markdown").addEventListener("click", () => {
    document.getElementById("tab-markdown").classList.add("active");
    document.getElementById("tab-events").classList.remove("active");
    document.getElementById("markdown-viewer").classList.remove("hidden");
    document.getElementById("event-log-list").classList.add("hidden");
  });

  // =========================================================================
  // 11. BOOTSTRAP ON STARTUP
  // =========================================================================
  document.getElementById("markdown-viewer").textContent = FALLBACK_TIMELINE_MD;
  loadGraphData(FALLBACK_DAG, "EMBEDDED M7 COMPOSITE KILL-CHAIN");

  // Also attempt automatic HTTP load if user is running a local web server
  fetch("../ephimtrace_dag.json", { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((data) => {
      if (data && Array.isArray(data.nodes)) {
        loadGraphData(data, "ephimtrace_dag.json");
      }
    })
    .catch(() => {});

  fetch("../ephimtrace_timeline.md", { cache: "no-store" })
    .then((r) => (r.ok ? r.text() : null))
    .then((md) => {
      if (md) document.getElementById("markdown-viewer").textContent = md;
    })
    .catch(() => {});

  requestAnimationFrame(renderFrame);
})();
