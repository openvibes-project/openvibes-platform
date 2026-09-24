import { type KeyboardEvent, useRef } from "react";

const menuItemSelector = '[role="menuitem"]';

export function HelpMenu() {
  const dialog = useRef<HTMLDialogElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  const moveMenuFocus = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      return;
    }

    const items = Array.from(event.currentTarget.querySelectorAll<HTMLElement>(menuItemSelector));
    const current = items.indexOf(document.activeElement as HTMLElement);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? items.length - 1
          : event.key === "ArrowDown"
            ? (current + 1) % items.length
            : (current - 1 + items.length) % items.length;

    event.preventDefault();
    items[next]?.focus();
  };

  const showAbout = () => {
    menu.current?.hidePopover();
    dialog.current?.showModal();
  };

  return (
    <div className="help-menu">
      <button
        ref={trigger}
        className="help-menu__trigger"
        type="button"
        popoverTarget="console-help-menu"
        aria-haspopup="menu"
      >
        Help
      </button>
      <div
        ref={menu}
        id="console-help-menu"
        className="help-menu__popover"
        popover="auto"
        role="menu"
        aria-label="Help"
        onKeyDown={moveMenuFocus}
        onToggle={(event) => {
          if (event.newState === "open") {
            event.currentTarget.querySelector<HTMLElement>(menuItemSelector)?.focus();
          }
        }}
      >
        <button type="button" role="menuitem" onClick={showAbout}>
          About this console
        </button>
        <a role="menuitem" href="/findings">
          Open findings
        </a>
      </div>
      <dialog
        ref={dialog}
        className="help-dialog"
        aria-labelledby="help-dialog-title"
        onClose={() => trigger.current?.focus()}
      >
        <form className="help-dialog__close" method="dialog">
          <button type="submit" aria-label="Close about this console dialog" autoFocus>
            ×
          </button>
        </form>
        <p className="eyebrow">OpenVIBES</p>
        <h2 id="help-dialog-title">About this console</h2>
        <p>
          This foundation keeps authentication and operational data unavailable until their
          database-backed boundaries are implemented.
        </p>
      </dialog>
    </div>
  );
}
