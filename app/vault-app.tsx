"use client";

import { FormEvent, useMemo, useState } from "react";

type Credential = {
  id: string;
  title: string;
  accountName: string;
  username: string;
  password: string;
  category: string;
  url: string;
  notes: string;
  updatedAt: string;
};

type VaultPayload = {
  credentials: Credential[];
};

type VaultEnvelope = {
  version: 1;
  username: string;
  salt: string;
  iv: string;
  data: string;
};

type AuthMode = "unlock" | "create";

const defaultCategories = ["Trabajo", "Personal", "Bancos", "Clientes"];
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const emptyForm = {
  title: "",
  accountName: "",
  username: "",
  password: "",
  category: "Trabajo",
  url: "",
  notes: "",
};

function normalizeUser(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, "-");
}

function vaultKey(username: string) {
  return `kentra:vault:${normalizeUser(username)}`;
}

function toBase64(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(value: string) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function asArrayBuffer(bytes: Uint8Array) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function getVaultKey(masterPassword: string, salt: Uint8Array) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(encoder.encode(masterPassword)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: asArrayBuffer(salt),
      iterations: 210000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVault(
  username: string,
  masterPassword: string,
  payload: VaultPayload,
  existingSalt?: string,
) {
  const salt = existingSalt ? fromBase64(existingSalt) : crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getVaultKey(masterPassword, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    key,
    asArrayBuffer(encoder.encode(JSON.stringify(payload))),
  );

  return {
    version: 1,
    username: username.trim(),
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
  } satisfies VaultEnvelope;
}

async function decryptVault(envelope: VaultEnvelope, masterPassword: string) {
  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const key = await getVaultKey(masterPassword, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    key,
    asArrayBuffer(fromBase64(envelope.data)),
  );

  return JSON.parse(decoder.decode(decrypted)) as VaultPayload;
}

function makePassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*?";
  const values = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(values, (value) => chars[value % chars.length]).join("");
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("es-CL", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function VaultApp() {
  const [mode, setMode] = useState<AuthMode>("unlock");
  const [username, setUsername] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [activeUser, setActiveUser] = useState("");
  const [salt, setSalt] = useState("");
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [form, setForm] = useState(emptyForm);
  const [selectedCategory, setSelectedCategory] = useState("Todas");
  const [query, setQuery] = useState("");
  const [visibleId, setVisibleId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const categories = useMemo(() => {
    const custom = credentials.map((credential) => credential.category).filter(Boolean);
    return ["Todas", ...Array.from(new Set([...defaultCategories, ...custom]))];
  }, [credentials]);

  const filteredCredentials = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return credentials
      .filter((credential) => selectedCategory === "Todas" || credential.category === selectedCategory)
      .filter((credential) => {
        if (!normalizedQuery) return true;
        return [credential.title, credential.accountName, credential.username, credential.category]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
      })
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }, [credentials, query, selectedCategory]);

  async function persist(nextCredentials: Credential[]) {
    const envelope = await encryptVault(
      activeUser,
      masterPassword,
      { credentials: nextCredentials },
      salt,
    );
    localStorage.setItem(vaultKey(activeUser), JSON.stringify(envelope));
    setSalt(envelope.salt);
    setCredentials(nextCredentials);
  }

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      const cleanUser = username.trim();
      if (!cleanUser || masterPassword.length < 8) {
        setMessage("Ingresa un usuario y una contraseña maestra de al menos 8 caracteres.");
        return;
      }

      const stored = localStorage.getItem(vaultKey(cleanUser));
      if (mode === "create") {
        if (stored) {
          setMessage("Ese usuario ya tiene una bóveda. Cambia a ingresar para abrirla.");
          return;
        }
        const envelope = await encryptVault(cleanUser, masterPassword, { credentials: [] });
        localStorage.setItem(vaultKey(cleanUser), JSON.stringify(envelope));
        setActiveUser(cleanUser);
        setSalt(envelope.salt);
        setCredentials([]);
        setMessage("Bóveda creada. Ya puedes guardar tus accesos.");
        return;
      }

      if (!stored) {
        setMessage("No encontré una bóveda para ese usuario. Puedes crearla ahora.");
        return;
      }

      const envelope = JSON.parse(stored) as VaultEnvelope;
      const payload = await decryptVault(envelope, masterPassword);
      setActiveUser(envelope.username);
      setSalt(envelope.salt);
      setCredentials(payload.credentials ?? []);
      setMessage("Bóveda desbloqueada.");
    } catch {
      setMessage("No pude abrir la bóveda. Revisa el usuario o la contraseña maestra.");
    } finally {
      setBusy(false);
    }
  }

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      const now = new Date().toISOString();
      const nextCredential: Credential = {
        id: editingId ?? crypto.randomUUID(),
        title: form.title.trim(),
        accountName: form.accountName.trim(),
        username: form.username.trim(),
        password: form.password,
        category: form.category.trim() || "Personal",
        url: form.url.trim(),
        notes: form.notes.trim(),
        updatedAt: now,
      };

      if (!nextCredential.title || !nextCredential.accountName || !nextCredential.password) {
        setMessage("Completa servicio, nombre asociado y contraseña.");
        return;
      }

      const nextCredentials = editingId
        ? credentials.map((credential) => (credential.id === editingId ? nextCredential : credential))
        : [nextCredential, ...credentials];

      await persist(nextCredentials);
      setForm(emptyForm);
      setEditingId(null);
      setMessage(editingId ? "Credencial actualizada." : "Credencial guardada.");
    } finally {
      setBusy(false);
    }
  }

  function startEdit(credential: Credential) {
    setEditingId(credential.id);
    setForm({
      title: credential.title,
      accountName: credential.accountName,
      username: credential.username,
      password: credential.password,
      category: credential.category,
      url: credential.url,
      notes: credential.notes,
    });
    setMessage("");
  }

  async function deleteCredential(id: string) {
    const nextCredentials = credentials.filter((credential) => credential.id !== id);
    await persist(nextCredentials);
    setMessage("Credencial eliminada.");
  }

  async function copyValue(value: string, label: string) {
    await navigator.clipboard.writeText(value);
    setMessage(`${label} copiado al portapapeles.`);
  }

  function lockVault() {
    setActiveUser("");
    setCredentials([]);
    setMasterPassword("");
    setForm(emptyForm);
    setEditingId(null);
    setVisibleId(null);
    setMessage("Bóveda bloqueada.");
  }

  if (!activeUser) {
    return (
      <main className="min-h-screen bg-[#f5f3ee] text-[#1e2528]">
        <section className="mx-auto flex min-h-screen w-full max-w-6xl items-center px-5 py-8">
          <div className="grid w-full gap-8 lg:grid-cols-[1fr_420px] lg:items-center">
            <div className="space-y-8">
              <div>
                <p className="text-sm font-semibold uppercase tracking-[0.28em] text-[#c05f3d]">
                  Kentra Vault
                </p>
                <h1 className="mt-4 max-w-3xl text-5xl font-semibold leading-tight text-[#172023] sm:text-7xl">
                  Tus accesos ordenados por usuario y categoría.
                </h1>
              </div>
              <p className="max-w-2xl text-lg leading-8 text-[#596266]">
                Guarda el nombre asociado a cada cuenta, su usuario y contraseña. La bóveda se cifra con
                tu contraseña maestra antes de quedar almacenada en este navegador.
              </p>
              <div className="grid max-w-2xl gap-3 sm:grid-cols-3">
                {["Cifrado local", "Categorías", "Copiado rápido"].map((item) => (
                  <div key={item} className="border border-[#ded8cc] bg-white/70 px-4 py-3 text-sm font-medium">
                    {item}
                  </div>
                ))}
              </div>
            </div>

            <form onSubmit={handleAuth} className="border border-[#d9d2c4] bg-white p-6 shadow-[0_24px_80px_rgba(39,32,21,0.12)]">
              <div className="mb-6 grid grid-cols-2 border border-[#d9d2c4] bg-[#f5f3ee] p-1">
                <button
                  type="button"
                  onClick={() => setMode("unlock")}
                  className={`h-11 text-sm font-semibold ${mode === "unlock" ? "bg-[#1e2528] text-white" : "text-[#596266]"}`}
                >
                  Ingresar
                </button>
                <button
                  type="button"
                  onClick={() => setMode("create")}
                  className={`h-11 text-sm font-semibold ${mode === "create" ? "bg-[#1e2528] text-white" : "text-[#596266]"}`}
                >
                  Crear
                </button>
              </div>

              <label className="block text-sm font-semibold text-[#384246]">
                Usuario
                <input
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  className="mt-2 h-12 w-full border border-[#d9d2c4] bg-white px-3 text-base outline-none focus:border-[#c05f3d]"
                  placeholder="tu-nombre"
                />
              </label>

              <label className="mt-4 block text-sm font-semibold text-[#384246]">
                Contraseña maestra
                <input
                  value={masterPassword}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  className="mt-2 h-12 w-full border border-[#d9d2c4] bg-white px-3 text-base outline-none focus:border-[#c05f3d]"
                  type="password"
                  placeholder="mínimo 8 caracteres"
                />
              </label>

              <button
                disabled={busy}
                className="mt-6 h-12 w-full bg-[#c05f3d] px-4 text-sm font-bold uppercase tracking-[0.16em] text-white transition hover:bg-[#a94f31] disabled:opacity-60"
              >
                {busy ? "Procesando" : mode === "create" ? "Crear bóveda" : "Desbloquear"}
              </button>
              {message ? <p className="mt-4 text-sm text-[#7b4a33]">{message}</p> : null}
            </form>
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#f5f3ee] text-[#1e2528]">
      <header className="border-b border-[#ddd6c9] bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[#c05f3d]">Kentra Vault</p>
            <h1 className="text-2xl font-semibold">Bóveda de {activeUser}</h1>
          </div>
          <button onClick={lockVault} className="h-10 border border-[#1e2528] px-4 text-sm font-semibold">
            Bloquear
          </button>
        </div>
      </header>

      <div className="mx-auto grid max-w-7xl gap-6 px-5 py-6 lg:grid-cols-[380px_1fr]">
        <section className="border border-[#d9d2c4] bg-white p-5">
          <h2 className="text-lg font-semibold">{editingId ? "Editar acceso" : "Nuevo acceso"}</h2>
          <form onSubmit={handleSave} className="mt-5 space-y-4">
            <InputField label="Servicio" value={form.title} onChange={(value) => setForm({ ...form, title: value })} placeholder="Gmail, Railway, Banco" />
            <InputField label="Nombre asociado" value={form.accountName} onChange={(value) => setForm({ ...form, accountName: value })} placeholder="Cuenta empresa, Juan Pérez" />
            <InputField label="Usuario o correo" value={form.username} onChange={(value) => setForm({ ...form, username: value })} placeholder="usuario@correo.com" />
            <label className="block text-sm font-semibold text-[#384246]">
              Contraseña
              <div className="mt-2 flex gap-2">
                <input
                  value={form.password}
                  onChange={(event) => setForm({ ...form, password: event.target.value })}
                  className="h-11 min-w-0 flex-1 border border-[#d9d2c4] px-3 text-base outline-none focus:border-[#c05f3d]"
                  type="text"
                  placeholder="Contraseña"
                />
                <button
                  type="button"
                  onClick={() => setForm({ ...form, password: makePassword() })}
                  className="h-11 border border-[#d9d2c4] px-3 text-sm font-semibold"
                >
                  Generar
                </button>
              </div>
            </label>
            <InputField label="Categoría" value={form.category} onChange={(value) => setForm({ ...form, category: value })} placeholder="Trabajo" />
            <InputField label="URL" value={form.url} onChange={(value) => setForm({ ...form, url: value })} placeholder="https://..." />
            <label className="block text-sm font-semibold text-[#384246]">
              Notas
              <textarea
                value={form.notes}
                onChange={(event) => setForm({ ...form, notes: event.target.value })}
                className="mt-2 min-h-24 w-full border border-[#d9d2c4] px-3 py-2 text-base outline-none focus:border-[#c05f3d]"
                placeholder="Detalle útil para reconocer esta cuenta"
              />
            </label>
            <div className="flex gap-2">
              <button disabled={busy} className="h-11 flex-1 bg-[#1e2528] px-4 text-sm font-bold text-white disabled:opacity-60">
                {editingId ? "Actualizar" : "Guardar"}
              </button>
              {editingId ? (
                <button
                  type="button"
                  onClick={() => {
                    setEditingId(null);
                    setForm(emptyForm);
                  }}
                  className="h-11 border border-[#d9d2c4] px-4 text-sm font-semibold"
                >
                  Cancelar
                </button>
              ) : null}
            </div>
          </form>
        </section>

        <section className="space-y-5">
          <div className="grid gap-3 border border-[#d9d2c4] bg-white p-4 md:grid-cols-[1fr_220px]">
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="h-11 border border-[#d9d2c4] px-3 text-base outline-none focus:border-[#c05f3d]"
              placeholder="Buscar por servicio, usuario o nombre"
            />
            <select
              value={selectedCategory}
              onChange={(event) => setSelectedCategory(event.target.value)}
              className="h-11 border border-[#d9d2c4] bg-white px-3 text-base outline-none focus:border-[#c05f3d]"
            >
              {categories.map((category) => (
                <option key={category}>{category}</option>
              ))}
            </select>
          </div>

          {message ? <p className="border border-[#ead1c2] bg-[#fff8f2] px-4 py-3 text-sm text-[#7b4a33]">{message}</p> : null}

          <div className="grid gap-3">
            {filteredCredentials.length ? (
              filteredCredentials.map((credential) => (
                <article key={credential.id} className="border border-[#d9d2c4] bg-white p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-xl font-semibold">{credential.title}</h3>
                        <span className="bg-[#eef0e7] px-2 py-1 text-xs font-semibold text-[#596266]">
                          {credential.category}
                        </span>
                      </div>
                      <p className="mt-1 text-sm text-[#596266]">{credential.accountName}</p>
                    </div>
                    <p className="text-xs text-[#7b8588]">Actualizado {formatDate(credential.updatedAt)}</p>
                  </div>

                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <div className="border border-[#eee7db] p-3">
                      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#7b8588]">Usuario</p>
                      <div className="mt-2 flex items-center gap-2">
                        <p className="min-w-0 flex-1 truncate font-medium">{credential.username || "Sin usuario"}</p>
                        {credential.username ? (
                          <button onClick={() => copyValue(credential.username, "Usuario")} className="text-sm font-semibold text-[#c05f3d]">
                            Copiar
                          </button>
                        ) : null}
                      </div>
                    </div>
                    <div className="border border-[#eee7db] p-3">
                      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#7b8588]">Contraseña</p>
                      <div className="mt-2 flex items-center gap-2">
                        <p className="min-w-0 flex-1 truncate font-mono">
                          {visibleId === credential.id ? credential.password : "••••••••••••"}
                        </p>
                        <button
                          onClick={() => setVisibleId(visibleId === credential.id ? null : credential.id)}
                          className="text-sm font-semibold text-[#596266]"
                        >
                          {visibleId === credential.id ? "Ocultar" : "Ver"}
                        </button>
                        <button onClick={() => copyValue(credential.password, "Contraseña")} className="text-sm font-semibold text-[#c05f3d]">
                          Copiar
                        </button>
                      </div>
                    </div>
                  </div>

                  {credential.url || credential.notes ? (
                    <div className="mt-3 text-sm leading-6 text-[#596266]">
                      {credential.url ? <p className="truncate">{credential.url}</p> : null}
                      {credential.notes ? <p>{credential.notes}</p> : null}
                    </div>
                  ) : null}

                  <div className="mt-4 flex gap-2">
                    <button onClick={() => startEdit(credential)} className="h-9 border border-[#d9d2c4] px-3 text-sm font-semibold">
                      Editar
                    </button>
                    <button onClick={() => deleteCredential(credential.id)} className="h-9 border border-[#ead1c2] px-3 text-sm font-semibold text-[#a94f31]">
                      Eliminar
                    </button>
                  </div>
                </article>
              ))
            ) : (
              <div className="border border-dashed border-[#cfc7b8] bg-white/70 p-8 text-center text-[#596266]">
                No hay accesos para este filtro.
              </div>
            )}
          </div>
        </section>
      </div>
    </main>
  );
}

function InputField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="block text-sm font-semibold text-[#384246]">
      {label}
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-2 h-11 w-full border border-[#d9d2c4] px-3 text-base outline-none focus:border-[#c05f3d]"
        placeholder={placeholder}
      />
    </label>
  );
}
