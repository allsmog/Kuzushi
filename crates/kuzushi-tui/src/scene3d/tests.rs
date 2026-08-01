use super::*;

fn cam(yaw: f32) -> Camera {
    Camera {
        yaw,
        pitch: 0.0,
        distance: 3.4,
    }
}

#[test]
fn project_keeps_origin_centered() {
    let p = project(cam(0.0), Vec3::new(0.0, 0.0, 0.0)).expect("origin projects");
    assert!(p.x.abs() < 1e-4);
    assert!(p.y.abs() < 1e-4);
}

#[test]
fn nearer_points_have_higher_depth_cue() {
    let near = project(cam(0.0), Vec3::new(0.0, 0.0, 1.0)).unwrap();
    let far = project(cam(0.0), Vec3::new(0.0, 0.0, -1.0)).unwrap();
    assert!(near.depth > far.depth);
}

#[test]
fn points_behind_the_eye_are_clipped() {
    // distance 3.4, so z = 3.4 is exactly at the eye → clipped.
    assert!(project(cam(0.0), Vec3::new(0.0, 0.0, 3.4)).is_none());
}

#[test]
fn yaw_rotation_moves_a_front_point_sideways() {
    let straight = project(cam(0.0), Vec3::new(1.0, 0.0, 0.0)).unwrap();
    let turned = project(cam(std::f32::consts::FRAC_PI_2), Vec3::new(1.0, 0.0, 0.0)).unwrap();
    // A quarter-turn swings the point toward/behind, changing its x.
    assert!((straight.x - turned.x).abs() > 0.1);
}

#[test]
fn viz_pages_cycle_and_wrap() {
    assert_eq!(VizPage::AttackSurface.next(), VizPage::AttackPath);
    assert_eq!(VizPage::AttackPath.next(), VizPage::Summary);
    assert_eq!(VizPage::Summary.next(), VizPage::Dfd);
    assert_eq!(VizPage::Dfd.next(), VizPage::EntryPoints);
    assert_eq!(VizPage::EntryPoints.next(), VizPage::Components);
    assert_eq!(VizPage::ExploitChain.next(), VizPage::Worklist);
    assert_eq!(VizPage::Worklist.next(), VizPage::AttackSurface);
    assert_eq!(VizPage::AttackSurface.prev(), VizPage::Worklist);
}

#[test]
fn only_attack_surface_is_3d_and_animated() {
    assert!(VizPage::AttackSurface.is_3d());
    assert!(VizPage::AttackSurface.is_animated());
    for page in [
        VizPage::AttackPath,
        VizPage::Summary,
        VizPage::Dfd,
        VizPage::EntryPoints,
        VizPage::Components,
        VizPage::Heatmap,
        VizPage::ExploitChain,
    ] {
        assert!(!page.is_3d(), "{page:?} should be 2D");
        assert!(!page.is_animated(), "{page:?} should be static");
    }
}

#[test]
fn attack_surface_terrain_builds_a_shaded_surface() {
    let scene = attack_surface_scene(&crate::ui_view_models::RiskByModule::default());
    assert!(
        scene.splats.len() > 100,
        "terrain should be a dense surface"
    );
    assert!(
        scene.splats.iter().all(|s| s.normal.is_some()),
        "surfels are lit"
    );
    assert_eq!(scene.title, "ATTACK SURFACE");
    assert!(!scene.subtitle.is_empty());
}
