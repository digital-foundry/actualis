//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static int appearanceIsDark(NSAppearance *a) {
    if (a == nil) {
        return -1;
    }
    NSAppearanceName best = [a bestMatchFromAppearancesWithNames:@[
        NSAppearanceNameAqua,
        NSAppearanceNameDarkAqua,
    ]];
    if (best == nil) {
        return -1;
    }
    return [best isEqualToString:NSAppearanceNameDarkAqua] ? 1 : 0;
}

// Must run on the main thread: AppKit's window list is not thread safe.
static int menuBarIsDarkOnMain(void) {
    // The status bar window is the only object that knows what the MENU BAR
    // is drawing. Its appearance is not the app's appearance: a translucent
    // menu bar over a light desktop picture renders light even while the
    // system is in Dark Mode, and only this window reflects that.
    //
    // Measured on a machine in Dark Mode with a light desktop picture:
    //     NSApp.effectiveAppearance          DARK
    //     NSAppearance.currentDrawingAppear. DARK
    //     AppleInterfaceStyle                Dark
    //     NSStatusBarWindow.effectiveAppear. LIGHT   <- matches the screen
    for (NSWindow *w in [NSApp windows]) {
        if ([NSStringFromClass([w class]) containsString:@"StatusBar"]) {
            int r = appearanceIsDark([w effectiveAppearance]);
            if (r >= 0) {
                return r;
            }
        }
    }
    // Before the status item exists there is nothing better to ask.
    return appearanceIsDark([NSApp effectiveAppearance]);
}

static int actualisMenuBarIsDark(void) {
    __block int result = -1;
    @autoreleasepool {
        if ([NSThread isMainThread]) {
            result = menuBarIsDarkOnMain();
        } else {
            dispatch_sync(dispatch_get_main_queue(), ^{
                result = menuBarIsDarkOnMain();
            });
        }
    }
    return result;
}
*/
import "C"

// menuBarIsDark reports whether the MENU BAR is drawing dark, and whether that
// could be determined at all. This is deliberately not the system appearance
// setting — see the C comment for the measurements that separate the two.
func menuBarIsDark() (dark, known bool) {
	switch int(C.actualisMenuBarIsDark()) {
	case 1:
		return true, true
	case 0:
		return false, true
	default:
		return false, false
	}
}
