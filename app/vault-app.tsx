"use client";

import { FormEvent, ReactNode, useMemo, useState } from "react";

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
  categories?: string[];
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

function makeEmptyForm(category = defaultCategories[0]) {
  return {
    title: "",
    accountName: "",
    username: "",
    password: "",
    category,
    url: "",
    notes: "",
  };
}

function cleanCategory(value: string) {
  return value.trim().replace(/\s+/g, " ");
}

function uniqueCategories(values: string[]) {
  return Array.from(new Set(values.map(cleanCategory).filter(Boolean)));
}

function hydratePayload(payload: VaultPayload) {
  const credentials = payload.credentials ?? [];
  const categories = uniqueCategories([
    ...(payload.categories?.length ? payload.categories : defaultCategories),
    ...credentials.map((credential) => credential.category),
  ]);

  return {
    credentials,
    categories: categories.length ? categories : defaultCategories,
  };
}

function normalizeUser(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, "-");
}

async function loadRemoteVault(username: string) {
  const response = await fetch(`/api/vaults?username=${encodeURIComponent(username)}`);

  if (!response.ok) {
    throw new Error("Unable to load vault.");
  }

  return (await response.json()) as { vault: VaultEnvelope | null };
}

async function saveRemoteVault(username: string, envelope: VaultEnvelope) {
  const response = await fetch("/api/vaults", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, envelope }),
  });

  if (!response.ok) {
    throw new Error("Unable to save vault.");
  }
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

function getInitial(value: string) {
  return value.trim().charAt(0).toUpperCase() || "K";
}

function getAvatarColor(value: string) {
  const colors = [
    "#2563eb",
    "#059669",
    "#d97706",
    "#e11d48",
    "#7c3aed",
    "#0891b2",
    "#4f46e5",
    "#db2777",
  ];
  return colors[(value.charCodeAt(0) || 0) % colors.length];
}

export function VaultApp() {
  const [mode, setMode] = useState<AuthMode>("unlock");
  const [username, setUsername] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [activeUser, setActiveUser] = useState("");
  const [salt, setSalt] = useState("");
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [categories, setCategories] = useState<string[]>(defaultCategories);
  const [form, setForm] = useState(makeEmptyForm());
  const [selectedCategory, setSelectedCategory] = useState("Todas");
  const [query, setQuery] = useState("");
  const [visibleId, setVisibleId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [isAccessSheetOpen, setIsAccessSheetOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [categoryName, setCategoryName] = useState("");
  const [editingCategory, setEditingCategory] = useState<string | null>(null);
  const [editingCategoryName, setEditingCategoryName] = useState("");
  const [categoryMessage, setCategoryMessage] = useState("");
  const [message, setMessage] = useState("");
  const [sheetMessage, setSheetMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const categoryOptions = useMemo(() => ["Todas", ...categories], [categories]);

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

  async function persist(nextCredentials: Credential[], nextCategories = categories) {
    const envelope = await encryptVault(
      normalizeUser(activeUser),
      masterPassword,
      { credentials: nextCredentials, categories: nextCategories },
      salt,
    );
    await saveRemoteVault(activeUser, envelope);
    setSalt(envelope.salt);
    setCredentials(nextCredentials);
    setCategories(nextCategories);
  }

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      const cleanUser = normalizeUser(username);
      if (!cleanUser || masterPassword.length < 8) {
        setMessage("Ingresa un usuario y una contraseña maestra de al menos 8 caracteres.");
        return;
      }

      const { vault } = await loadRemoteVault(cleanUser);
      if (mode === "create") {
        if (vault) {
          setMessage("Ese usuario ya tiene una bóveda. Cambia a ingresar para abrirla.");
          return;
        }
        const envelope = await encryptVault(cleanUser, masterPassword, {
          credentials: [],
          categories: defaultCategories,
        });
        await saveRemoteVault(cleanUser, envelope);
        setActiveUser(cleanUser);
        setSalt(envelope.salt);
        setCredentials([]);
        setCategories(defaultCategories);
        setForm(makeEmptyForm(defaultCategories[0]));
        setMessage("Bóveda creada. Ya puedes guardar tus accesos.");
        return;
      }

      if (!vault) {
        setMessage("No encontré una bóveda para ese usuario. Puedes crearla ahora.");
        return;
      }

      const payload = hydratePayload(await decryptVault(vault, masterPassword));
      setActiveUser(vault.username);
      setSalt(vault.salt);
      setCredentials(payload.credentials);
      setCategories(payload.categories);
      setForm(makeEmptyForm(payload.categories[0]));
      setMessage("Bóveda desbloqueada.");
    } catch {
      setMessage("No pude abrir la bóveda. Revisa el usuario, la contraseña maestra o la conexión a la base de datos.");
    } finally {
      setBusy(false);
    }
  }

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setSheetMessage("");

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
        setSheetMessage("Completa servicio, nombre asociado y contraseña.");
        return;
      }

      const nextCredentials = editingId
        ? credentials.map((credential) => (credential.id === editingId ? nextCredential : credential))
        : [nextCredential, ...credentials];

      await persist(nextCredentials);
      setForm(makeEmptyForm(categories[0]));
      setEditingId(null);
      setIsAccessSheetOpen(false);
      setMessage(editingId ? "Credencial actualizada." : "Credencial guardada.");
    } catch {
      setSheetMessage("No pude guardar en la base de datos. Revisa la conexión e intenta nuevamente.");
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
    setIsAccessSheetOpen(true);
    setIsSettingsOpen(false);
    setSheetMessage("");
    setMessage("");
  }

  async function deleteCredential(id: string) {
    try {
      const nextCredentials = credentials.filter((credential) => credential.id !== id);
      await persist(nextCredentials);
      setMessage("Credencial eliminada.");
    } catch {
      setMessage("No pude eliminar en la base de datos. Revisa la conexión e intenta nuevamente.");
    }
  }

  async function handleCreateCategory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCategoryMessage("");

    const nextCategory = cleanCategory(categoryName);
    if (!nextCategory) {
      setCategoryMessage("Ingresa un nombre para la categoría.");
      return;
    }

    if (categories.some((category) => category.toLowerCase() === nextCategory.toLowerCase())) {
      setCategoryMessage("Esa categoría ya existe.");
      return;
    }

    try {
      const nextCategories = [...categories, nextCategory];
      await persist(credentials, nextCategories);
      setCategoryName("");
      setCategoryMessage("Categoría creada.");
    } catch {
      setCategoryMessage("No pude guardar la categoría en la base de datos.");
    }
  }

  async function handleUpdateCategory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCategoryMessage("");

    if (!editingCategory) return;

    const nextCategory = cleanCategory(editingCategoryName);
    if (!nextCategory) {
      setCategoryMessage("Ingresa un nombre para la categoría.");
      return;
    }

    const duplicate = categories.some(
      (category) =>
        category.toLowerCase() === nextCategory.toLowerCase() &&
        category.toLowerCase() !== editingCategory.toLowerCase(),
    );
    if (duplicate) {
      setCategoryMessage("Esa categoría ya existe.");
      return;
    }

    try {
      const nextCategories = categories.map((category) =>
        category === editingCategory ? nextCategory : category,
      );
      const nextCredentials = credentials.map((credential) =>
        credential.category === editingCategory
          ? { ...credential, category: nextCategory, updatedAt: new Date().toISOString() }
          : credential,
      );

      await persist(nextCredentials, nextCategories);
      if (selectedCategory === editingCategory) setSelectedCategory(nextCategory);
      if (form.category === editingCategory) setForm({ ...form, category: nextCategory });
      setEditingCategory(null);
      setEditingCategoryName("");
      setCategoryMessage("Categoría actualizada.");
    } catch {
      setCategoryMessage("No pude actualizar la categoría en la base de datos.");
    }
  }

  async function deleteCategory(categoryToDelete: string) {
    setCategoryMessage("");

    if (categories.length <= 1) {
      setCategoryMessage("Debe existir al menos una categoría.");
      return;
    }

    if (credentials.some((credential) => credential.category === categoryToDelete)) {
      setCategoryMessage("No puedes eliminar una categoría con accesos asociados. Reasigna esos accesos primero.");
      return;
    }

    try {
      const nextCategories = categories.filter((category) => category !== categoryToDelete);
      await persist(credentials, nextCategories);
      if (selectedCategory === categoryToDelete) setSelectedCategory("Todas");
      if (form.category === categoryToDelete) setForm({ ...form, category: nextCategories[0] });
      if (editingCategory === categoryToDelete) {
        setEditingCategory(null);
        setEditingCategoryName("");
      }
      setCategoryMessage("Categoría eliminada.");
    } catch {
      setCategoryMessage("No pude eliminar la categoría en la base de datos.");
    }
  }

  async function copyValue(value: string, label: string) {
    await navigator.clipboard.writeText(value);
    setMessage(`${label} copiado al portapapeles.`);
  }

  function closeSettings() {
    setIsSettingsOpen(false);
    setCategoryName("");
    setEditingCategory(null);
    setEditingCategoryName("");
    setCategoryMessage("");
  }

  function lockVault() {
    setActiveUser("");
    setCredentials([]);
    setCategories(defaultCategories);
    setMasterPassword("");
    setForm(makeEmptyForm(categories[0]));
    setEditingId(null);
    setVisibleId(null);
    setIsAccessSheetOpen(false);
    setIsSettingsOpen(false);
    setCategoryName("");
    setEditingCategory(null);
    setEditingCategoryName("");
    setCategoryMessage("");
    setSheetMessage("");
    setMessage("Bóveda bloqueada.");
  }

  if (!activeUser) {
    return (
      <main className="min-h-screen bg-background text-foreground">
        <section className="mx-auto flex min-h-screen w-full max-w-md items-center px-4 py-8">
          <div className="w-full">
            <div className="mb-8 flex items-center justify-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-foreground text-background">
                <LockIcon />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                  Kentra
                </p>
                <h1 className="text-2xl font-semibold leading-tight text-foreground">Vault</h1>
              </div>
            </div>

            <form onSubmit={handleAuth} className="rounded-xl border border-border bg-card p-5 shadow-sm sm:p-6">
              <div className="mb-6 grid grid-cols-2 rounded-lg border border-border bg-muted p-1">
                <button
                  type="button"
                  onClick={() => setMode("unlock")}
                  className={`h-10 rounded-md text-sm font-semibold transition ${mode === "unlock" ? "bg-card text-foreground shadow-sm" : "text-muted-foreground"}`}
                >
                  Ingresar
                </button>
                <button
                  type="button"
                  onClick={() => setMode("create")}
                  className={`h-10 rounded-md text-sm font-semibold transition ${mode === "create" ? "bg-card text-foreground shadow-sm" : "text-muted-foreground"}`}
                >
                  Crear
                </button>
              </div>

              <label className="block text-sm font-medium text-foreground">
                Usuario
                <input
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  className="mt-2 h-11 w-full rounded-md border border-input bg-background px-3 text-base outline-none transition focus:border-ring"
                  autoComplete="username"
                  autoCapitalize="none"
                  autoCorrect="off"
                  placeholder="tu-nombre"
                />
              </label>

              <label className="mt-4 block text-sm font-medium text-foreground">
                Contraseña maestra
                <input
                  value={masterPassword}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  className="mt-2 h-11 w-full rounded-md border border-input bg-background px-3 text-base outline-none transition focus:border-ring"
                  type="password"
                  autoComplete={mode === "create" ? "new-password" : "current-password"}
                  placeholder="mínimo 8 caracteres"
                />
              </label>

              <button
                disabled={busy}
                className="mt-6 h-11 w-full rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground transition hover:opacity-90 disabled:opacity-60"
              >
                {busy ? "Procesando" : mode === "create" ? "Crear bóveda" : "Desbloquear"}
              </button>
              {message ? <p className="mt-4 rounded-md border border-border bg-muted px-3 py-2 text-sm text-muted-foreground">{message}</p> : null}
            </form>
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border bg-card/85 backdrop-blur-sm">
        <div className="mx-auto flex max-w-4xl items-center justify-between gap-3 px-4 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-foreground text-background">
              <LockIcon />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">Kentra Vault</p>
              <h1 className="truncate text-sm font-semibold leading-tight text-foreground">{activeUser}</h1>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              onClick={() => {
                setEditingId(null);
                setForm(makeEmptyForm(categories[0]));
                setIsAccessSheetOpen(true);
                setIsSettingsOpen(false);
                setSheetMessage("");
                setMessage("");
              }}
              className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground transition hover:opacity-90"
              aria-label="Nuevo acceso"
              title="Nuevo acceso"
            >
              <PlusIcon />
            </button>
            <button
              onClick={() => {
                setIsSettingsOpen(true);
                setIsAccessSheetOpen(false);
                setEditingId(null);
                setSheetMessage("");
                setCategoryMessage("");
              }}
              className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground transition hover:bg-muted hover:text-foreground"
              aria-label="Catálogo"
              title="Catálogo"
            >
              <SettingsIcon />
            </button>
            <button
              onClick={lockVault}
              className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground transition hover:bg-muted hover:text-foreground"
              aria-label="Bloquear bóveda"
              title="Bloquear bóveda"
            >
              <LockIcon />
            </button>
          </div>
        </div>
      </header>

      {isAccessSheetOpen ? (
        <SheetPanel
          titleId="access-sheet-title"
          eyebrow={editingId ? "Editar acceso" : "Nuevo acceso"}
          title={editingId ? "Actualizar credencial" : "Guardar nueva credencial"}
          description="Registra el servicio, el nombre asociado a la cuenta y sus datos de ingreso."
          onClose={() => {
            setIsAccessSheetOpen(false);
            setEditingId(null);
            setForm(makeEmptyForm(categories[0]));
            setSheetMessage("");
          }}
        >
          <form onSubmit={handleSave} className="grid gap-4 px-5 py-5">
            {sheetMessage ? (
              <p className="rounded-md border border-border bg-muted px-4 py-3 text-sm text-muted-foreground">
                {sheetMessage}
              </p>
            ) : null}
            <InputField label="Servicio" value={form.title} onChange={(value) => setForm({ ...form, title: value })} placeholder="Gmail, Railway, Banco" />
            <InputField label="Nombre asociado" value={form.accountName} onChange={(value) => setForm({ ...form, accountName: value })} placeholder="Cuenta empresa, Juan Pérez" />
            <InputField label="Usuario o correo" value={form.username} onChange={(value) => setForm({ ...form, username: value })} placeholder="usuario@correo.com" />
            <label className="block text-sm font-medium text-foreground">
              Contraseña
              <div className="mt-2 flex gap-2">
                <input
                  value={form.password}
                  onChange={(event) => setForm({ ...form, password: event.target.value })}
                  className="h-10 min-w-0 flex-1 rounded-md border border-input bg-background px-3 text-base outline-none transition focus:border-ring"
                  type="text"
                  placeholder="Contraseña"
                />
                <button
                  type="button"
                  onClick={() => setForm({ ...form, password: makePassword() })}
                  className="h-10 rounded-md border border-border px-3 text-sm font-semibold transition hover:bg-muted"
                >
                  Generar
                </button>
              </div>
            </label>
            <label className="block text-sm font-medium text-foreground">
              Categoría
              <select
                value={form.category}
                onChange={(event) => setForm({ ...form, category: event.target.value })}
                className="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-base outline-none transition focus:border-ring"
              >
                {categories.map((category) => (
                  <option key={category} value={category}>
                    {category}
                  </option>
                ))}
              </select>
            </label>
            <InputField label="URL" value={form.url} onChange={(value) => setForm({ ...form, url: value })} placeholder="https://..." />
            <label className="block text-sm font-medium text-foreground">
              Notas
              <textarea
                value={form.notes}
                onChange={(event) => setForm({ ...form, notes: event.target.value })}
                className="mt-2 min-h-24 w-full rounded-md border border-input bg-background px-3 py-2 text-base outline-none transition focus:border-ring"
                placeholder="Detalle útil para reconocer esta cuenta"
              />
            </label>
            <div className="sticky bottom-0 -mx-5 mt-2 flex gap-2 border-t border-border bg-card/95 px-5 py-4 backdrop-blur">
              <button disabled={busy} className="h-10 flex-1 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground disabled:opacity-60">
                {editingId ? "Actualizar" : "Guardar"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setIsAccessSheetOpen(false);
                  setEditingId(null);
                  setForm(makeEmptyForm(categories[0]));
                  setSheetMessage("");
                }}
                className="h-10 rounded-md border border-border px-4 text-sm font-semibold transition hover:bg-muted"
              >
                Cancelar
              </button>
            </div>
          </form>
        </SheetPanel>
      ) : null}

      {isSettingsOpen ? (
        <SheetPanel
          titleId="catalog-sheet-title"
          eyebrow="Catálogo"
          title="Categorías"
          description="Administra las categorías disponibles para ordenar tus accesos."
          onClose={closeSettings}
        >
          <div className="grid gap-5 px-5 py-5">
            <form onSubmit={handleCreateCategory} className="grid gap-3 sm:grid-cols-[1fr_auto]">
              <input
                value={categoryName}
                onChange={(event) => setCategoryName(event.target.value)}
                className="h-10 rounded-md border border-input bg-background px-3 text-base outline-none transition focus:border-ring"
                placeholder="Nueva categoría"
              />
              <button disabled={busy} className="h-10 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground disabled:opacity-60">
                Agregar
              </button>
            </form>

            {categoryMessage ? (
              <p className="rounded-md border border-border bg-muted px-4 py-3 text-sm text-muted-foreground">
                {categoryMessage}
              </p>
            ) : null}

            <div className="grid gap-2">
              {categories.map((category) => {
                const usageCount = credentials.filter((credential) => credential.category === category).length;

                return (
                  <article key={category} className="rounded-md border border-border bg-background p-3">
                    {editingCategory === category ? (
                      <form onSubmit={handleUpdateCategory} className="grid gap-2 sm:grid-cols-[1fr_auto_auto]">
                        <input
                          value={editingCategoryName}
                          onChange={(event) => setEditingCategoryName(event.target.value)}
                          className="h-10 rounded-md border border-input bg-card px-3 text-base outline-none transition focus:border-ring"
                        />
                        <button disabled={busy} className="h-10 rounded-md bg-primary px-3 text-sm font-semibold text-primary-foreground disabled:opacity-60">
                          Guardar
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setEditingCategory(null);
                            setEditingCategoryName("");
                            setCategoryMessage("");
                          }}
                          className="h-10 rounded-md border border-border px-3 text-sm font-semibold transition hover:bg-muted"
                        >
                          Cancelar
                        </button>
                      </form>
                    ) : (
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                          <p className="font-semibold text-foreground">{category}</p>
                          <p className="text-sm text-muted-foreground">
                            {usageCount === 1 ? "1 acceso asociado" : `${usageCount} accesos asociados`}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              setEditingCategory(category);
                              setEditingCategoryName(category);
                              setCategoryMessage("");
                            }}
                            className="h-9 rounded-md border border-border px-3 text-sm font-semibold transition hover:bg-muted"
                          >
                            Editar
                          </button>
                          <button
                            type="button"
                            onClick={() => void deleteCategory(category)}
                            className="h-9 rounded-md border border-border px-3 text-sm font-semibold text-destructive transition hover:bg-muted"
                          >
                            Eliminar
                          </button>
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>

            <div className="sticky bottom-0 -mx-5 mt-2 flex justify-end border-t border-border bg-card/95 px-5 py-4 backdrop-blur">
              <button
                type="button"
                onClick={closeSettings}
                className="h-10 rounded-md border border-border px-4 text-sm font-semibold transition hover:bg-muted"
              >
                Cerrar
              </button>
            </div>
          </div>
        </SheetPanel>
      ) : null}

      <div className="mx-auto grid max-w-4xl gap-5 px-4 py-4 md:py-6">
        <section className="min-w-0 space-y-5">
          <div className="grid min-w-0 gap-3">
            <div className="relative">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                <SearchIcon />
              </span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="h-10 w-full rounded-md border border-input bg-card px-9 text-base outline-none transition focus:border-ring"
                placeholder="Buscar..."
              />
              {query ? (
                <button
                  type="button"
                  onClick={() => setQuery("")}
                  className="absolute right-1 top-1/2 inline-flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition hover:bg-muted hover:text-foreground"
                  aria-label="Limpiar búsqueda"
                  title="Limpiar búsqueda"
                >
                  <XIcon />
                </button>
              ) : null}
            </div>

            <div className="flex flex-wrap gap-2" aria-label="Filtrar por categoría">
              {categoryOptions.map((category) => (
                <button
                  key={category}
                  type="button"
                  onClick={() => setSelectedCategory(category)}
                  aria-pressed={selectedCategory === category}
                  className={`h-9 rounded-full border px-3 text-sm font-medium transition ${
                    selectedCategory === category
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground"
                  }`}
                >
                  {category}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              {filteredCredentials.length} {filteredCredentials.length === 1 ? "credencial" : "credenciales"}
            </p>
            <div className="flex items-center gap-1.5 text-xs text-emerald-600">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Bóveda desbloqueada
            </div>
          </div>

          {message ? <p className="rounded-md border border-border bg-muted px-4 py-3 text-sm text-muted-foreground">{message}</p> : null}

          <div className="grid min-w-0 gap-3">
            {filteredCredentials.length ? (
              filteredCredentials.map((credential) => (
                <article key={credential.id} className="group min-w-0 rounded-lg border border-border bg-card shadow-sm transition hover:border-muted-foreground/30">
                  <div className="flex items-center gap-2 p-3 md:gap-3 md:p-4">
                    <div
                      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-semibold text-white sm:h-10 sm:w-10"
                      style={{ backgroundColor: getAvatarColor(credential.title) }}
                    >
                      {getInitial(credential.title)}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="mb-0.5 flex min-w-0 items-center gap-2">
                        <h3 className="min-w-0 truncate font-medium text-foreground">{credential.title}</h3>
                        <span className="hidden shrink-0 rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground sm:inline-flex">
                          {credential.category}
                        </span>
                      </div>
                      <p className="truncate text-sm text-muted-foreground">{credential.username || credential.accountName}</p>
                    </div>

                    <div className="flex shrink-0 items-center justify-end gap-0.5 sm:gap-1">
                      {credential.username ? (
                        <IconButton
                          label="Copiar usuario"
                          title="Copiar usuario"
                          compact
                          onClick={() => copyValue(credential.username, "Usuario")}
                        >
                          <CopyIcon />
                        </IconButton>
                      ) : null}
                      <IconButton
                        label={visibleId === credential.id ? "Ocultar contraseña" : "Ver contraseña"}
                        title={visibleId === credential.id ? "Ocultar contraseña" : "Ver contraseña"}
                        compact
                        onClick={() => setVisibleId(visibleId === credential.id ? null : credential.id)}
                      >
                        {visibleId === credential.id ? <EyeOffIcon /> : <EyeIcon />}
                      </IconButton>
                      <IconButton
                        label="Copiar contraseña"
                        title="Copiar contraseña"
                        compact
                        onClick={() => copyValue(credential.password, "Contraseña")}
                      >
                        <CopyIcon />
                      </IconButton>
                      <IconButton label="Editar acceso" title="Editar acceso" compact onClick={() => startEdit(credential)}>
                        <PencilIcon />
                      </IconButton>
                      <IconButton
                        label="Eliminar acceso"
                        title="Eliminar acceso"
                        compact
                        danger
                        onClick={() => deleteCredential(credential.id)}
                      >
                        <TrashIcon />
                      </IconButton>
                    </div>
                  </div>

                  {visibleId === credential.id ? (
                    <div className="px-3 pb-3 md:px-4 md:pb-4">
                      <div className="rounded-md bg-muted px-3 py-2 font-mono text-sm break-all text-foreground">
                        {credential.password}
                      </div>
                      <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                        {credential.accountName ? <p>{credential.accountName}</p> : null}
                        {credential.url ? <p className="truncate">{credential.url}</p> : null}
                        {credential.notes ? <p>{credential.notes}</p> : null}
                        <p>Actualizado: {formatDate(credential.updatedAt)}</p>
                      </div>
                    </div>
                  ) : null}
                </article>
              ))
            ) : (
              <div className="rounded-lg border border-dashed border-border bg-card p-8 text-center text-muted-foreground">
                <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <LockIcon />
                </div>
                <h3 className="font-medium text-foreground">{query || selectedCategory !== "Todas" ? "Sin resultados" : "Bóveda vacía"}</h3>
                <p className="mt-1 text-sm">
                  {query || selectedCategory !== "Todas"
                    ? "No se encontraron credenciales con esos filtros."
                    : "Agrega tu primera credencial para comenzar."}
                </p>
                {!credentials.length ? (
                  <button
                    onClick={() => {
                      setEditingId(null);
                      setForm(makeEmptyForm(categories[0]));
                      setIsAccessSheetOpen(true);
                      setIsSettingsOpen(false);
                      setSheetMessage("");
                    }}
                    className="mt-4 inline-flex h-10 items-center gap-1.5 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground"
                  >
                    <PlusIcon />
                    Crear primer acceso
                  </button>
                ) : null}
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
    <label className="block text-sm font-medium text-foreground">
      {label}
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-base outline-none transition focus:border-ring"
        placeholder={placeholder}
      />
    </label>
  );
}

function IconButton({
  label,
  title,
  accent = false,
  compact = false,
  danger = false,
  children,
  onClick,
}: {
  label: string;
  title: string;
  accent?: boolean;
  compact?: boolean;
  danger?: boolean;
  children: ReactNode;
  onClick: () => void;
}) {
  const tone = danger
    ? "text-destructive hover:bg-destructive/10"
    : accent
      ? "text-accent hover:bg-accent/10"
      : "text-muted-foreground hover:bg-muted hover:text-foreground";

  return (
    <button
      type="button"
      aria-label={label}
      title={title}
      onClick={onClick}
      className={`inline-flex shrink-0 items-center justify-center rounded-md transition ${compact ? "h-8 w-8 sm:h-9 sm:w-9" : "h-11 w-11"} ${tone}`}
    >
      {children}
    </button>
  );
}

function CopyIcon() {
  return (
    <svg aria-hidden="true" className="h-5 w-5" viewBox="0 0 24 24" fill="none">
      <path
        d="M8 8.5C8 7.12 9.12 6 10.5 6H18C19.1 6 20 6.9 20 8V18C20 19.1 19.1 20 18 20H10.5C9.12 20 8 18.88 8 17.5V8.5Z"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M5 15.5V5.5C5 4.67 5.67 4 6.5 4H15"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function EyeIcon() {
  return (
    <svg aria-hidden="true" className="h-5 w-5" viewBox="0 0 24 24" fill="none">
      <path
        d="M3 12C5.4 7.9 8.4 6 12 6C15.6 6 18.6 7.9 21 12C18.6 16.1 15.6 18 12 18C8.4 18 5.4 16.1 3 12Z"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
      <path
        d="M12 14.8C13.55 14.8 14.8 13.55 14.8 12C14.8 10.45 13.55 9.2 12 9.2C10.45 9.2 9.2 10.45 9.2 12C9.2 13.55 10.45 14.8 12 14.8Z"
        stroke="currentColor"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function EyeOffIcon() {
  return (
    <svg aria-hidden="true" className="h-5 w-5" viewBox="0 0 24 24" fill="none">
      <path d="M4 4L20 20" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
      <path
        d="M10.2 6.25C10.78 6.08 11.38 6 12 6C15.6 6 18.6 7.9 21 12C20.22 13.33 19.38 14.43 18.47 15.31"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="1.8"
      />
      <path
        d="M14.1 14.42C13.55 14.82 12.83 15 12 15C10.34 15 9 13.66 9 12C9 11.2 9.24 10.51 9.72 9.92"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="1.8"
      />
      <path
        d="M7.53 8.09C5.86 8.94 4.35 10.24 3 12C5.4 16.1 8.4 18 12 18C13.15 18 14.23 17.81 15.25 17.4"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path
        d="M7 10V8C7 5.24 9.24 3 12 3C14.76 3 17 5.24 17 8V10"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="2"
      />
      <path
        d="M6.5 10H17.5C18.6 10 19.5 10.9 19.5 12V19C19.5 20.1 18.6 21 17.5 21H6.5C5.4 21 4.5 20.1 4.5 19V12C4.5 10.9 5.4 10 6.5 10Z"
        stroke="currentColor"
        strokeWidth="2"
      />
    </svg>
  );
}

function PlusIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path d="M12 5V19M5 12H19" stroke="currentColor" strokeLinecap="round" strokeWidth="2" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 15.5A3.5 3.5 0 1 0 12 8.5A3.5 3.5 0 0 0 12 15.5Z"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M19.4 15A1.65 1.65 0 0 0 19.73 16.82L19.8 16.89A2 2 0 1 1 16.97 19.72L16.9 19.65A1.65 1.65 0 0 0 15.08 19.32A1.65 1.65 0 0 0 14.08 20.83V21A2 2 0 1 1 10.08 21V20.9A1.65 1.65 0 0 0 9 19.39A1.65 1.65 0 0 0 7.18 19.72L7.11 19.79A2 2 0 1 1 4.28 16.96L4.35 16.89A1.65 1.65 0 0 0 4.68 15.07A1.65 1.65 0 0 0 3.17 14H3A2 2 0 1 1 3 10H3.1A1.65 1.65 0 0 0 4.61 8.92A1.65 1.65 0 0 0 4.28 7.1L4.21 7.03A2 2 0 1 1 7.04 4.2L7.11 4.27A1.65 1.65 0 0 0 8.93 4.6H9A1.65 1.65 0 0 0 10 3.09V3A2 2 0 1 1 14 3V3.1A1.65 1.65 0 0 0 15 4.61A1.65 1.65 0 0 0 16.82 4.28L16.89 4.21A2 2 0 1 1 19.72 7.04L19.65 7.11A1.65 1.65 0 0 0 19.32 8.93V9A1.65 1.65 0 0 0 20.83 10H21A2 2 0 1 1 21 14H20.9A1.65 1.65 0 0 0 19.4 15Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.5"
      />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path
        d="M10.8 18.2A7.4 7.4 0 1 0 10.8 3.4A7.4 7.4 0 0 0 10.8 18.2Z"
        stroke="currentColor"
        strokeWidth="2"
      />
      <path d="M16.1 16.1L21 21" stroke="currentColor" strokeLinecap="round" strokeWidth="2" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path d="M6 6L18 18M18 6L6 18" stroke="currentColor" strokeLinecap="round" strokeWidth="2" />
    </svg>
  );
}

function PencilIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path
        d="M4 20H8L18.5 9.5C19.6 8.4 19.6 6.6 18.5 5.5C17.4 4.4 15.6 4.4 14.5 5.5L4 16V20Z"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function TrashIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path d="M4 7H20" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
      <path d="M10 11V17M14 11V17" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
      <path
        d="M6.5 7L7.4 19C7.48 20.12 8.42 21 9.55 21H14.45C15.58 21 16.52 20.12 16.6 19L17.5 7"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path d="M9 7V5C9 3.9 9.9 3 11 3H13C14.1 3 15 3.9 15 5V7" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}

function SheetPanel({
  titleId,
  eyebrow,
  title,
  description,
  onClose,
  children,
}: {
  titleId: string;
  eyebrow: string;
  title: string;
  description: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div
      className="kentra-sheet-backdrop"
      data-state="open"
      role="presentation"
    >
      <aside
        className="kentra-sheet-card"
        data-state="open"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-border bg-card/95 px-5 py-5 backdrop-blur">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">{eyebrow}</p>
            <h2 id={titleId} className="mt-3 text-2xl font-semibold text-foreground">
              {title}
            </h2>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-muted-foreground transition hover:bg-muted hover:text-foreground"
            aria-label="Cerrar"
            title="Cerrar"
          >
            <XIcon />
          </button>
        </div>

        {children}
      </aside>
    </div>
  );
}
