import Foundation

/// Where "Start server" and "Invite friends" lead on a Mac that hosts.
///
/// An invite can only be made by the OWNER's account, and that account exists only once owner
/// setup has run (`HostWizardView`: start the server, ask the owner's name, sign this Mac in).
/// Build 44 let the menu bar start a server without it, and then offered an invite panel that
/// had nobody to make the invite: it span, and no join code ever appeared. So every entry point
/// asks here first, and without an owner on this Mac they all lead to the setup. Foundation
/// only (compiled into the logic tests as it is).
enum HostSetupRoute {
    enum Action { case startServer, inviteFriends }

    enum Screen: Equatable {
        /// Nothing to show (the menu bar's Start on a Mac that is already set up).
        case none
        /// The full setup: starts the server if needed, asks the owner's name, signs in, then
        /// shows the invite.
        case setupWizard
        case invitePanel
    }

    struct Decision: Equatable {
        var screen: Screen
        /// Start the server now (the wizard does it itself when it opens with this set).
        var startServer: Bool
    }

    /// - Parameters:
    ///   - hasOwnerWorkspace: this Mac is signed in to its own server as the owner.
    ///   - serverUp: the server is running or on its way up (starting, restarting).
    static func decide(_ action: Action, hasOwnerWorkspace: Bool, serverUp: Bool) -> Decision {
        switch (action, hasOwnerWorkspace) {
        case (.startServer, true):
            return Decision(screen: .none, startServer: !serverUp)          // as before
        case (.startServer, false):
            return Decision(screen: .setupWizard, startServer: !serverUp)
        case (.inviteFriends, true):
            // As before while it runs. With the server off there is no address to invite to:
            // the wizard is where it gets started.
            return serverUp ? Decision(screen: .invitePanel, startServer: false) : Decision(screen: .setupWizard, startServer: false)
        case (.inviteFriends, false):
            return Decision(screen: .setupWizard, startServer: !serverUp)
        }
    }
}
